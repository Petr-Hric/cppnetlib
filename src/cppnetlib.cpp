#include "cppnetlib/cppnetlib.h"

#include "cppnetlib/endian/endian.h"
#include "cppnetlib/platform/platform.h"

#include <algorithm>
#include <cassert>
#include <iostream>

#define SOCKET_OP_SUCCESSFUL 0

// #define CPPNLTEST

#ifdef CPPNLTEST
#define DEFAULT_TCP_SEND_TIMEOUT 5000
#define DEFAULT_TCP_RECV_TIMEOUT 5000

#define DEFAULT_TCP_CONNECT_TIMEOUT 5000
#define DEFAULT_TCP_ACCEPT_TIMEOUT 5000

#define DEFAULT_UDP_SENDTO_TIMEOUT 5000
#define DEFAULT_UDP_RECVFROM_TIMEOUT 5000
#else
#define DEFAULT_TCP_SEND_TIMEOUT 60000
#define DEFAULT_TCP_RECV_TIMEOUT 60000

#define DEFAULT_TCP_CONNECT_TIMEOUT 60000
#define DEFAULT_TCP_ACCEPT_TIMEOUT 60000

#define DEFAULT_UDP_SENDTO_TIMEOUT 60000
#define DEFAULT_UDP_RECVFROM_TIMEOUT 60000
#endif

namespace cppnetlib {
    // Global constants

    static constexpr platform::IoDataSizeT cMaxTransmitionUnitSize = MAX_TRANSMISSION_UNIT;

    namespace exception {
        class UnknownAddressFamilyException : public Exception {
        public:
            UnknownAddressFamilyException(std::string function)
                : Exception(function + " -> Unknown address family") {}
        };

        class ExceptionWithSystemErrorMessage : public Exception {
        public:
            ExceptionWithSystemErrorMessage(std::string function, std::string message)
                : Exception(function + " -> " + message + " [" + std::to_string(platform::nativeErrorCode()) +
                            " | Native message - " + error::toString(platform::nativeErrorCode()) + "]") {}
        };

        class ConnectionTimeoutException : public Exception {
        public:
            ConnectionTimeoutException(std::string function)
                : Exception(function + " -> Connection timeout") {}
        };
    } // namespace exception

    namespace helpers {
        platform::SockLenT toSockLen(const Address& address);
    }
    sockaddr createSockAddr(const Address& address);

    // Platform dependent definitions/declarations

#if defined PLATFORM_WINDOWS

    namespace error {
        std::string toString(const NativeErrorCodeT value) {
            std::string output;
            char* message = nullptr;
            FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                               FORMAT_MESSAGE_IGNORE_INSERTS,
                           nullptr,
                           value,
                           MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                           (LPSTR)&message,
                           0,
                           nullptr);
            output = message;
            LocalFree(message);
            return output;
        }
    } // namespace error

    namespace platform {
        class Winsock {
        public:
            Winsock() {
                if (WSAStartup(WS_VERSION, &wsad) != 0) {
                    throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                                                                     "Could not initialize WinSock");
                }
            }

            ~Winsock() {
                try {
                    if (WSACleanup() != 0) {
                        throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                                                                         "Could not deinitialize WinSock");
                    }
                } catch (...) {
                }
            }

        private:
            WSAData wsad;
        };

        static Winsock winsock;

        inline error::NativeErrorCodeT nativeErrorCode() { return WSAGetLastError(); }

        SocketT nativeSocketOpen(const NativeFamilyT addressFamily, const int ipProtocol) {
            static std::mutex mtx;
            std::lock_guard<std::mutex> lock(mtx);

            int type = 0;
            switch (ipProtocol) {
            case IPPROTO_TCP:
                type = SOCK_STREAM;
                break;
            case IPPROTO_UDP:
                type = SOCK_DGRAM;
                break;
            default:
                assert(false);
                throw Exception(FUNC_NAME + ": Unknown addressFamily value");
            }

            const platform::SocketT socket = ::socket(addressFamily, type, ipProtocol);
            if (socket == INVALID_SOCKET_DESCRIPTOR) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not open socket");
            }

            return socket;
        }

        void nativeSocketClose(platform::SocketT& socket) {
            if (::shutdown(socket, SD_BOTH) != 0) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not shutdown socket");
            }

            if (::closesocket(socket) != SOCKET_OP_SUCCESSFUL) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not close socket");
            }
            socket = INVALID_SOCKET_DESCRIPTOR;
        }

        error::IOReturnValue nativeConnect(platform::SocketT& socket, const Address& address) {
            const sockaddr sockAddr = createSockAddr(address);
            if (::connect(socket, &sockAddr, helpers::toSockLen(address)) != SOCKET_OP_SUCCESSFUL) {
                if (nativeErrorCode() == WSAEWOULDBLOCK) {
                    return error::IOReturnValue::OpWouldBlock;
                }
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                                                                 "Could not connect to the server");
            }
            return error::IOReturnValue::Successful;
        }

        inline bool nativeSetBlocked(platform::SocketT socket, const bool blocked) {
            u_long mode = blocked ? 0U : 1U;
            return ioctlsocket(socket, FIONBIO, &mode) != SOCKET_OP_UNSUCCESSFUL;
        }

        // For older Winsock2 versions
        void nativeInetNtop(const NativeFamilyT addressFamily,
                            const void* src,
                            char* dst,
                            const std::size_t dstMaxSize) {
            assert(src != nullptr);
            assert(dst != nullptr);

            DWORD s =
                static_cast<DWORD>(std::min<std::size_t>(std::numeric_limits<DWORD>::max(), dstMaxSize));
            sockaddr_storage sockAddrStorage = {};
            sockAddrStorage.ss_family = addressFamily;

            char buffer[16] = {};
            switch (addressFamily) {
            case AF_INET:
                std::copy(reinterpret_cast<const char*>(src),
                          reinterpret_cast<const char*>(src) + sizeof(sockaddr_in::sin_addr),
                          buffer);
                std::copy(
                    reinterpret_cast<const in_addr*>(buffer),
                    reinterpret_cast<const in_addr*>(buffer) + sizeof(in_addr),
                    reinterpret_cast<in_addr*>(&reinterpret_cast<sockaddr_in*>(&sockAddrStorage)->sin_addr));
                break;
            case AF_INET6:
                std::copy(reinterpret_cast<const char*>(src),
                          reinterpret_cast<const char*>(src) + sizeof(sockaddr_in6::sin6_addr),
                          buffer);
                std::copy(reinterpret_cast<const in6_addr*>(buffer),
                          reinterpret_cast<const in6_addr*>(buffer) + sizeof(in6_addr),
                          reinterpret_cast<in6_addr*>(
                              &reinterpret_cast<sockaddr_in6*>(&sockAddrStorage)->sin6_addr));
                break;
            default:
                throw exception::UnknownAddressFamilyException(FUNC_NAME);
            }

            if (WSAAddressToStringA(reinterpret_cast<sockaddr*>(&sockAddrStorage),
                                    sizeof(sockAddrStorage),
                                    nullptr,
                                    dst,
                                    &s) != 0) {
                throw exception::ExceptionWithSystemErrorMessage(
                    FUNC_NAME, "Could not convert address to human readable format");
            }
        }

        // For older Winsock2 versions
        void nativeInetPton(const NativeFamilyT addressFamily, const char* src, void* dst) {
            assert(src != nullptr);
            assert(dst != nullptr);

            sockaddr_storage sockAddrStorage = {};
            int size = sizeof(sockAddrStorage);
            char scrCopy[INET6_ADDRSTRLEN + 1U] = {};

            std::copy(src, src + INET6_ADDRSTRLEN + 1U, scrCopy);

            if (WSAStringToAddressA(
                    scrCopy, addressFamily, nullptr, (struct sockaddr*)&sockAddrStorage, &size) == 0) {
                switch (addressFamily) {
                case AF_INET:
                    *reinterpret_cast<in_addr*>(dst) =
                        (reinterpret_cast<sockaddr_in*>(&sockAddrStorage))->sin_addr;
                    break;
                case AF_INET6:
                    *reinterpret_cast<in6_addr*>(dst) =
                        (reinterpret_cast<sockaddr_in6*>(&sockAddrStorage))->sin6_addr;
                    break;
                default:
                    throw exception::UnknownAddressFamilyException(FUNC_NAME);
                }
            } else {
                throw exception::ExceptionWithSystemErrorMessage(
                    FUNC_NAME, "Could not convert address to network format");
            }
        }
    } // namespace platform

#elif defined PLATFORM_LINUX

    namespace error {
        std::string toString(const NativeErrorCodeT value) { return std::strerror(value); }
    } // namespace error

    namespace platform {
        inline error::NativeErrorCodeT nativeErrorCode() { return errno; }

        SocketT nativeSocketOpen(const NativeFamilyT addressFamily, const int ipProtocol) {
            int type = 0;
            switch (ipProtocol) {
            case IPPROTO_TCP:
                type = SOCK_STREAM;
                break;
            case IPPROTO_UDP:
                type = SOCK_DGRAM;
                break;
            default:
                assert(false);
                throw Exception(FUNC_NAME + ": Unknown addressFamily value");
            }

            const platform::SocketT socket = ::socket(addressFamily, type, ipProtocol);
            if (socket == INVALID_SOCKET_DESCRIPTOR) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not create socket");
            }

            return socket;
        }

        void nativeSocketClose(platform::SocketT socket) {
            if (::shutdown(socket, SD_BOTH) != 0) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not shutdown socket");
            }

            if (::close(socket) != SOCKET_OP_SUCCESSFUL) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not close socket");
            }
        }

        error::IOReturnValue nativeConnect(platform::SocketT& socket, const Address& address) {
            const sockaddr sockAddr = createSockAddr(address);
            if (::connect(socket, &sockAddr, helpers::toSockLen(address)) != SOCKET_OP_SUCCESSFUL) {
                if (nativeErrorCode() == EWOULDBLOCK) {
                    error::IOReturnValue::OpWouldBlock;
                }
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                                                                 "Could not connect to the server");
            }
            return error::IOReturnValue::Successful;
        }

        bool nativeSetBlocked(platform::SocketT socket, const bool blocked) {
            int flags = fcntl(socket, F_GETFL, 0);
            if (flags == -1) {
                return false;
            }

            flags = blocked ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);

            if (fcntl(socket, F_SETFL, flags) == -1) {
                return false;
            }
            return true;
        }

        void nativeInetPton(const NativeFamilyT addressFamily, const char* src, void* dst) {
            assert(src != nullptr);
            assert(dst != nullptr);
            const int retv = inet_pton(addressFamily, src, dst);

            if (retv == 0) {
                throw Exception(FUNC_NAME +
                                ": Could not convert address to network format, because the input string is "
                                "not valid address");
            } else if (retv == -1) {
                throw Exception(
                    FUNC_NAME +
                    ": Could not convert address to network format, because the IP version is unknown");
            } else if (retv != 1) {
                throw exception::ExceptionWithSystemErrorMessage(
                    FUNC_NAME, "Could not convert address to network format");
            } // else: Operation successful
        }

        inline void nativeInetNtop(const NativeFamilyT addressFamily,
                                   const void* src,
                                   char* dst,
                                   const std::size_t dstMaxSize) {
            if (inet_ntop(addressFamily, src, dst, dstMaxSize) == nullptr) {
                throw exception::ExceptionWithSystemErrorMessage(
                    FUNC_NAME, "Could not convert network address to human readable format");
            }
        }
    } // namespace platform

#else

#error Unsupported platform!

#endif

    // Helpers

    namespace helpers {
        platform::NativeFamilyT toNativeFamily(const IPVer ipVersion) {
            switch (ipVersion) {
            case IPVer::IPv4:
                return AF_INET;
            case IPVer::IPv6:
                return AF_INET6;
            default:
                assert(false);
                throw exception::UnknownAddressFamilyException(FUNC_NAME);
            }
        }

        platform::SockLenT toSockLen(const IPVer ipVersion) {
            switch (ipVersion) {
            case IPVer::IPv4:
                return sizeof(sockaddr_in);
            case IPVer::IPv6:
                return sizeof(sockaddr_in6);
            default:
                assert(false);
                throw Exception(FUNC_NAME + ": Unknown IPVer value");
            }
        }

        platform::SockLenT toSockLen(const Address& address) { return toSockLen(address.ip().version()); }

        IPVer toIPVer(const platform::NativeFamilyT addressFamily) {
            switch (addressFamily) {
            case AF_INET:
                return IPVer::IPv4;
            case AF_INET6:
                return IPVer::IPv6;
            default:
                throw exception::UnknownAddressFamilyException(FUNC_NAME);
            }
        }
    } // namespace helpers

    // Exception

    Exception::Exception(std::string message)
        : mMessage(std::move(message)) {}

    const std::string& Exception::message() const { return mMessage; }

    // Ip

    Ip::Ip()
        : mIpVer(IPVer::Unknown) {}

    Ip::Ip(const Ip& other)
        : mIpVer(other.mIpVer)
        , mIpStr(other.mIpStr) {}

    Ip::Ip(Ip&& other)
        : mIpVer(std::move(other.mIpVer))
        , mIpStr(std::move(other.mIpStr)) {}

    Ip::Ip(const char* ip)
        : mIpVer(IPVer::Unknown) {
        assert(ip != nullptr);
        *this = ip;
    }

    Ip::Ip(const std::string& ip)
        : mIpVer(IPVer::Unknown) {
        *this = ip;
    }

    const std::string& Ip::string() const { return mIpStr; }

    IPVer Ip::version() const { return mIpVer; }

    bool Ip::operator==(const Ip& other) const { return mIpStr == other.mIpStr; }

    bool Ip::operator!=(const Ip& other) const { return !(mIpStr == other.mIpStr); }

    Ip& Ip::operator=(const Ip& other) {
        mIpVer = other.mIpVer;
        mIpStr = other.mIpStr;
        return *this;
    }

    Ip& Ip::operator=(Ip&& other) {
        mIpVer = std::exchange(other.mIpVer, IPVer::Unknown);
        mIpStr = std::move(other.mIpStr);
        return *this;
    }

    Ip& Ip::operator=(const char* ip) {
        assert(ip != nullptr);
        return this->operator=(std::string(ip));
    }

    Ip& Ip::operator=(const std::string& ip) {
        if (ip.empty()) {
            mIpStr.clear();
        } else {
            if (isIpV4Addr(ip)) {
                mIpVer = IPVer::IPv4;
            } else if (isIpV6Addr(ip)) {
                mIpVer = IPVer::IPv6;
            } else {
                throw Exception("Invalid IP format");
            }
            mIpStr = ip;
        }
        return *this;
    }

    bool Ip::operator<(const Ip& other) const { return mIpStr < other.mIpStr; }

    bool Ip::isIpV4Addr(const std::string& ip) {
        struct sockaddr_in sa;
        try {
            platform::nativeInetPton(AF_INET, ip.c_str(), &sa);
        } catch (const exception::UnknownAddressFamilyException&) {
            return false;
        }
        return true;
    }

    bool Ip::isIpV6Addr(const std::string& ip) {
        struct sockaddr_in6 sa;
        try {
            platform::nativeInetPton(AF_INET6, ip.c_str(), &sa);
        } catch (const exception::UnknownAddressFamilyException&) {
            return false;
        }
        return true;
    }

    // Address

    Address::Address(const Address& other) { *this = other; }

    Address::Address(Address&& other) { *this = std::move(other); }

    Address::Address(const Ip& ip, const PortT port) {
        mIp = ip;
        mPort = port;
    }

    Address& Address::operator=(const Address& other) {
        mIp = other.mIp;
        mPort = other.mPort;
        return *this;
    }

    Address& Address::operator=(Address&& other) {
        mIp = std::move(other.mIp);
        mPort = std::move(other.mPort);
        return *this;
    }

    bool Address::operator==(const Address& other) const { return mIp == other.mIp && mPort == other.mPort; }

    bool Address::operator!=(const Address& other) const { return mIp != other.mIp || mPort != other.mPort; }

    bool Address::operator<(const Address& other) const {
        return mIp == other.mIp ? (mPort < other.mPort) : (mIp < other.mIp);
    }

    const Ip& Address::ip() const { return mIp; }

    PortT Address::port() const { return mPort; }

    sockaddr createSockAddr(const Address& address) {
        sockaddr sockAddr = {};

        switch (address.ip().version()) {
        case IPVer::IPv4: {
            sockaddr_in& ipv4addr = reinterpret_cast<sockaddr_in&>(sockAddr);
            ipv4addr.sin_family = helpers::toNativeFamily(address.ip().version());
            ipv4addr.sin_port = Endian::convertNativeTo(address.port(), Endian::Type::Big);
            platform::nativeInetPton(helpers::toNativeFamily(address.ip().version()),
                                     address.ip().string().c_str(),
                                     &ipv4addr.sin_addr);
            break;
        }
        case IPVer::IPv6: {
            sockaddr_in6& ipv6addr = reinterpret_cast<sockaddr_in6&>(sockAddr);
            ipv6addr.sin6_family = helpers::toNativeFamily(address.ip().version());
            ipv6addr.sin6_port = Endian::convertNativeTo(address.port(), Endian::Type::Big);
            platform::nativeInetPton(helpers::toNativeFamily(address.ip().version()),
                                     address.ip().string().c_str(),
                                     &ipv6addr.sin6_addr);
            break;
        }
        default:
            throw Exception(FUNC_NAME + ": Unknown IPVer value");
        }
        return sockAddr;
    }

    Address createAddress(const sockaddr& sockAddr) {
        PortT port;
        char ipBuffer[40] = {};

        switch (sockAddr.sa_family) {
        case AF_INET: {
            const sockaddr_in& ipv4addr = reinterpret_cast<const sockaddr_in&>(sockAddr);
            port = Endian::convertToNative(ipv4addr.sin_port, Endian::Type::Big);
            platform::nativeInetNtop(AF_INET, &ipv4addr.sin_addr, ipBuffer, sizeof(ipBuffer));
            break;
        }
        case AF_INET6: {
            const sockaddr_in6& ipv6addr = reinterpret_cast<const sockaddr_in6&>(sockAddr);
            port = Endian::convertToNative(ipv6addr.sin6_port, Endian::Type::Big);
            platform::nativeInetNtop(AF_INET, &ipv6addr.sin6_addr, ipBuffer, sizeof(ipBuffer));
            break;
        }
        default:
            throw exception::UnknownAddressFamilyException(FUNC_NAME);
        }
        return Address(ipBuffer, port);
    }

    // Error

    namespace error {
        std::string toString(const IOReturnValue value) {
            assert(static_cast<std::size_t>(value) < 3);
            static const std::string errorMessage[] = { { "Operation should be blocked" },
                                                        { "Gracefully disconnected" } };

            return errorMessage[static_cast<size_t>(value)];
        }
    } // namespace error

    // Base namespace

    namespace base {
        SocketBase::SocketBase()
            : mBlocking(false)
            , mSocket(INVALID_SOCKET_DESCRIPTOR) {}

        SocketBase::SocketBase(platform::SocketT&& socket)
            : mBlocking(false)
            , mSocket(std::exchange(socket, INVALID_SOCKET_DESCRIPTOR)) {
            setBlocked(false);
        }

        SocketBase::SocketBase(SocketBase&& other) { *this = std::move(other); }

        SocketBase::~SocketBase() {
            try {
                if (this->isSocketOpen()) {
                    this->close();
                }
            } catch (...) {
            }
        }

        SocketBase& SocketBase::operator=(SocketBase&& other) {
            mSocket = std::exchange(other.mSocket, INVALID_SOCKET_DESCRIPTOR);
            mBlocking = other.mBlocking;
            return *this;
        }

        void SocketBase::close() {
            if (!isSocketOpen()) {
                throw Exception(FUNC_NAME + ": Could not close socket, because the socket is already closed");
            }
            platform::nativeSocketClose(mSocket);
        }

        void SocketBase::bind(const Address& address) {
            if (!isSocketOpen()) {
                openSocket(address.ip().version());
            }

            const sockaddr sockAddr = createSockAddr(address);
            const platform::NetLibRetvT retv = ::bind(mSocket, &sockAddr, helpers::toSockLen(address));
            if (retv == SOCKET_OP_UNSUCCESSFUL) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                                                                 "Could not bind address to socket");
            } else if (retv != SOCKET_OP_SUCCESSFUL) {
                throw Exception(FUNC_NAME + ": Unknown error occured");
            } // else: Operation successful
        }

        void SocketBase::setBlocked(const bool blocked) {
            if (!isSocketOpen()) {
                throw Exception(FUNC_NAME + ": Socket is not open");
            }

            if (!platform::nativeSetBlocked(mSocket, blocked)) {
                throw exception::ExceptionWithSystemErrorMessage(
                    FUNC_NAME, "Could not set blocking/non-blocking socket property");
            }

            mBlocking = blocked;
        }

        bool SocketBase::blocked() const { return mBlocking; }

        bool SocketBase::isSocketOpen() const { return mSocket != INVALID_SOCKET_DESCRIPTOR; }

        bool SocketBase::rwTimeout(const OpTimeout selectTimeoutFor, const Timeout timeout) const {
            if (!isSocketOpen()) {
                throw Exception(FUNC_NAME +
                                ": Could not perform connect/accept timeout, because the socket is not open");
            }

            fd_set fdSet;
            fd_set* fdWritePtr = nullptr;
            fd_set* fdReadPtr = nullptr;

            switch (selectTimeoutFor) {
            case OpTimeout::Write:
                fdWritePtr = &fdSet;
                break;
            case OpTimeout::Read:
                fdReadPtr = &fdSet;
                break;
            default:
                throw Exception("Unknown value of SelectTimeout");
            }

            FD_ZERO(&fdSet);
            FD_SET(mSocket, &fdSet);

            timeval tv;
            tv.tv_sec = timeout / 1000;
            tv.tv_usec = timeout % 1000 * 1000;

            const int selectRetv = select(static_cast<int>(mSocket + 1), fdReadPtr, fdWritePtr, nullptr, &tv);
            if (selectRetv == 0) {
                return true;
            } else if (selectRetv == SOCKET_OP_UNSUCCESSFUL) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not perform select");
            } else {
                if (FD_ISSET(mSocket, &fdSet) <= 0) {
                    throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                                                                     "Could not connect to the server");
                }
            }
            return false;
        }

        void SocketBase::setWriteReadTimeout(const OpTimeout opTimeoutFor, const Timeout timeout) {
            if (!isSocketOpen()) {
                throw Exception(FUNC_NAME +
                                ": Could not set write/read timeout, because the socket is not open");
            }

#if defined PLATFORM_WINDOWS
            switch (opTimeoutFor) {
            case OpTimeout::Write:
                if (setsockopt(mSocket,
                               SOL_SOCKET,
                               SO_SNDTIMEO,
                               reinterpret_cast<const char*>(&timeout),
                               sizeof(timeout)) != 0) {
                    throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                                                                     "Could not set write operation timeout");
                }
                break;
            case OpTimeout::Read:
                if (setsockopt(mSocket,
                               SOL_SOCKET,
                               SO_RCVTIMEO,
                               reinterpret_cast<const char*>(&timeout),
                               sizeof(timeout)) != 0) {
                    throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                                                                     "Could not set read operation timeout");
                }
                break;
            default:
                throw Exception("Unknown OpTimeout value");
            }
#elif defined PLATFORM_LINUX
            switch (opTimeoutFor) {
            case OpTimeout::Write:
                if (setsockopt(mSocket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
                    exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                                                               "Could not set write operation timeout");
                }
                break;
            case OpTimeout::Read:
                if (setsockopt(mSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
                    exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                                                               "Could not set read operation timeout");
                }
                break;
            default:
                throw Exception("Unknown OpTimeout value");
            }
#else
#error Unsupported platform
#endif
        }

        TCPSocketBase::TCPSocketBase()
            : SocketBase()
            , mSendTimeout(DEFAULT_TCP_SEND_TIMEOUT)
            , mRecvTimeout(DEFAULT_TCP_RECV_TIMEOUT)
            , mConnectTimeout(DEFAULT_TCP_CONNECT_TIMEOUT)
            , mAcceptTimeout(DEFAULT_TCP_ACCEPT_TIMEOUT) {}

        TCPSocketBase::TCPSocketBase(TCPSocketBase&& other)
            : SocketBase(std::move(dynamic_cast<SocketBase&>(other)))
            , mSendTimeout(std::move(other.mSendTimeout))
            , mRecvTimeout(std::move(other.mRecvTimeout))
            , mConnectTimeout(std::move(other.mConnectTimeout))
            , mAcceptTimeout(std::move(other.mAcceptTimeout)) {}

        TCPSocketBase::TCPSocketBase(platform::SocketT&& socket)
            : SocketBase(std::move(socket))
            , mSendTimeout(DEFAULT_TCP_SEND_TIMEOUT)
            , mRecvTimeout(DEFAULT_TCP_RECV_TIMEOUT)
            , mConnectTimeout(DEFAULT_TCP_CONNECT_TIMEOUT)
            , mAcceptTimeout(DEFAULT_TCP_ACCEPT_TIMEOUT) {
            socket = INVALID_SOCKET_DESCRIPTOR;
        }

        TCPSocketBase& TCPSocketBase::operator=(TCPSocketBase&& other) {
            mSendTimeout = std::move(other.mSendTimeout);
            mRecvTimeout = std::move(other.mRecvTimeout);
            mConnectTimeout = std::move(other.mConnectTimeout);
            mAcceptTimeout = std::move(other.mAcceptTimeout);

            SocketBase::operator=(std::move(static_cast<base::SocketBase&>(other)));

            return *this;
        }

        TCPSocketBase::~TCPSocketBase() {}

        void TCPSocketBase::openSocket(const IPVer ipVer) {
            if (isSocketOpen()) {
                throw Exception(FUNC_NAME + ": Could not open socket, the socket is already open");
            }
            mSocket = platform::nativeSocketOpen(helpers::toNativeFamily(ipVer), IPPROTO_TCP);

            setBlocked(false);
        }

        void TCPSocketBase::connect(const Address& address) {
            if (!isSocketOpen()) {
                openSocket(address.ip().version());
            }

            const error::IOReturnValue errorCode = platform::nativeConnect(mSocket, address);
            switch (errorCode) {
            case error::IOReturnValue::Successful:
                return;
            case error::IOReturnValue::OpWouldBlock:
                if (getConnectTimeout() > 0 && rwTimeout(OpTimeout::Write, getConnectTimeout())) {
                    throw exception::ConnectionTimeoutException(FUNC_NAME);
                }
                break;
            default:
                assert(false);
                throw Exception("Unknown error code " + std::to_string(static_cast<int>(errorCode)));
            }
        }

        void TCPSocketBase::listen(const std::size_t backlogSize) const {
            if (!isSocketOpen()) {
                throw Exception(FUNC_NAME +
                                ": Could not open socket for listening, because the socket is not open");
            }

            if (::listen(mSocket,
                         static_cast<int>(std::min<std::size_t>(std::numeric_limits<int>::max(),
                                                                backlogSize))) != SOCKET_OP_SUCCESSFUL) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                                                                 "Could not open socket for listening");
            }
        }

        void
        TCPSocketBase::tryAccept(const std::function<void(platform::SocketT&&, Address&&, void*)>& onAccept,
                                 void* userArg) const {
            sockaddr addr = {};

            if (rwTimeout(OpTimeout::Read, mAcceptTimeout)) {
                return;
            }

            platform::SockLenT sockLen = helpers::toSockLen(IPVer::IPv6 /*Max sockaddr size*/);
            platform::SocketT socket = ::accept(mSocket, &addr, &sockLen);
            if (socket == INVALID_SOCKET_DESCRIPTOR) {
                if (platform::nativeErrorCode() != CPPNL_OPWOULDBLOCK) {
                    throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not accept client");
                }
            }

            onAccept(std::move(socket), createAddress(addr), userArg);
        }

        IOResult TCPSocketBase::send(const TransmitDataT* data, const std::size_t size) {
            assert(data != nullptr);
            if (!isSocketOpen()) {
                throw Exception(FUNC_NAME + ": Could not send data, because the socket is not open");
            }

            if (rwTimeout(OpTimeout::Write, mSendTimeout)) {
                return error::makeError<std::size_t, error::IOReturnValue>(
                    error::IOReturnValue::OperationTimedOut);
            }

            const platform::NetLibRetvT retv =
                ::send(mSocket,
                       reinterpret_cast<const platform::NativeTransmitDataT*>(data),
                       static_cast<platform::IoDataSizeT>(
                           std::min<std::size_t>(static_cast<std::size_t>(cMaxTransmitionUnitSize), size)),
                       0);
            if (retv == SOCKET_OP_UNSUCCESSFUL) {
                if (platform::nativeErrorCode() == CPPNL_OPWOULDBLOCK) {
                    return error::makeError<std::size_t, error::IOReturnValue>(
                        error::IOReturnValue::OpWouldBlock);
                }
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not send data");
            }

            assert(retv >= 0);

            return static_cast<std::size_t>(retv);
        }

        IOResult TCPSocketBase::receive(TransmitDataT* data, const std::size_t maxSize) {
            assert(data != nullptr);
            if (!isSocketOpen()) {
                throw Exception(FUNC_NAME + ": Could not receive data, because the socket is not open");
            }

            if (rwTimeout(OpTimeout::Read, mRecvTimeout)) {
                return error::makeError<std::size_t, error::IOReturnValue>(
                    error::IOReturnValue::OperationTimedOut);
            }

            const platform::NetLibRetvT retv =
                ::recv(mSocket,
                       reinterpret_cast<platform::NativeTransmitDataT*>(data),
                       static_cast<platform::IoDataSizeT>(
                           std::min<std::size_t>(static_cast<std::size_t>(cMaxTransmitionUnitSize), maxSize)),
                       0);

            if (retv == SOCKET_OP_UNSUCCESSFUL) {
                if (platform::nativeErrorCode() == CPPNL_OPWOULDBLOCK) {
                    return error::makeError<std::size_t, error::IOReturnValue>(
                        error::IOReturnValue::OpWouldBlock);
                } else if (platform::nativeErrorCode() == CPPNL_FORCEDISCONNECT ||
                           platform::nativeErrorCode() == CPPNL_CONNECTIONABORT) {
                    return error::makeError<std::size_t, error::IOReturnValue>(
                        error::IOReturnValue::ForciblyDisconnected);
                }
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not recv data");
            } else if (retv == 0) {
                return error::makeError<std::size_t, error::IOReturnValue>(
                    error::IOReturnValue::GracefullyDisconnected);
            }

            assert(retv > 0);

            return static_cast<std::size_t>(retv);
        }

        void TCPSocketBase::setTimeout(const TCPTimeoutFor timeoutFor, const Timeout timeoutMs) {
            switch (timeoutFor) {
            case TCPTimeoutFor::Send:
                mSendTimeout = timeoutMs;
                // setWriteReadTimeout(OpTimeout::Write, timeoutMs);
                break;
            case TCPTimeoutFor::Recieve:
                mRecvTimeout = timeoutMs;
                // setWriteReadTimeout(OpTimeout::Read, timeoutMs);
                break;
            case TCPTimeoutFor::Connect:
                mConnectTimeout = timeoutMs;
                break;
            case TCPTimeoutFor::Accept:
                mAcceptTimeout = timeoutMs;
                break;
            default:
                throw Exception("Unknwon TCPTimeoutFor value");
            }
        }

        UDPSocketBase::UDPSocketBase()
            : SocketBase()
            , mSendToTimeout(DEFAULT_UDP_SENDTO_TIMEOUT)
            , mRecvFromTimeout(DEFAULT_UDP_RECVFROM_TIMEOUT) {}

        UDPSocketBase::UDPSocketBase(UDPSocketBase&& other)
            : SocketBase(std::move(dynamic_cast<SocketBase&>(other)))
            , mSendToTimeout(std::move(other.mSendToTimeout))
            , mRecvFromTimeout(std::move(other.mRecvFromTimeout)) {}

        UDPSocketBase::~UDPSocketBase() {}

        void UDPSocketBase::openSocket(const IPVer ipVer) {
            if (isSocketOpen()) {
                throw Exception(FUNC_NAME + ": Could not open socket, the socket is already open");
            }
            mSocket = platform::nativeSocketOpen(helpers::toNativeFamily(ipVer), IPPROTO_UDP);

            setBlocked(false);
        }

        IOResult
        UDPSocketBase::sendTo(const TransmitDataT* data, const std::size_t size, const Address& address) {
            assert(data != nullptr);

            if (!isSocketOpen()) {
                openSocket(address.ip().version());
            }

            if (rwTimeout(OpTimeout::Write, mSendToTimeout)) {
                return error::makeError<std::size_t, error::IOReturnValue>(
                    error::IOReturnValue::OperationTimedOut);
            }

            const sockaddr sockAddr = createSockAddr(address);
            const platform::NetLibRetvT retv =
                ::sendto(mSocket,
                         reinterpret_cast<const platform::NativeTransmitDataT*>(data),
                         static_cast<platform::IoDataSizeT>(
                             std::min<std::size_t>(static_cast<std::size_t>(cMaxTransmitionUnitSize), size)),
                         0,
                         &sockAddr,
                         helpers::toSockLen(address));

            if (retv == SOCKET_OP_UNSUCCESSFUL) {
                if (platform::nativeErrorCode() == CPPNL_OPWOULDBLOCK) {
                    return error::makeError<std::size_t, error::IOReturnValue>(
                        error::IOReturnValue::OpWouldBlock);
                }
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not send data");
            }

            assert(retv > 0);

            return static_cast<std::size_t>(retv);
        }

        IOResult
        UDPSocketBase::receiveFrom(TransmitDataT* data, const std::size_t maxSize, Address& address) {
            assert(data != nullptr);

            if (!isSocketOpen()) {
                openSocket(address.ip().version());
            }

            if (rwTimeout(OpTimeout::Read, mRecvFromTimeout)) {
                return error::makeError<std::size_t, error::IOReturnValue>(
                    error::IOReturnValue::OperationTimedOut);
            }

            sockaddr sockAddr = {};
            platform::SockLenT sockLen = helpers::toSockLen(IPVer::IPv6);
            const platform::NetLibRetvT retv =
                ::recvfrom(mSocket,
                           reinterpret_cast<platform::NativeTransmitDataT*>(data),
                           static_cast<platform::IoDataSizeT>(std::min<std::size_t>(
                               static_cast<std::size_t>(cMaxTransmitionUnitSize), maxSize)),
                           0,
                           &sockAddr,
                           &sockLen);

            if (retv == SOCKET_OP_UNSUCCESSFUL) {
                if (platform::nativeErrorCode() == CPPNL_OPWOULDBLOCK) {
                    return error::makeError<std::size_t, error::IOReturnValue>(
                        error::IOReturnValue::OpWouldBlock);
                }
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not receive data");
            }

            address = createAddress(sockAddr);

            assert(sockLen == helpers::toSockLen(address));
            assert(retv > 0);

            return static_cast<std::size_t>(retv);
        }

        void UDPSocketBase::setTimeout(const UDPTimeoutFor timeoutFor, const Timeout timeoutMs) {
            switch (timeoutFor) {
            case UDPTimeoutFor::SendTo:
                mSendToTimeout = timeoutMs;
                setWriteReadTimeout(OpTimeout::Write, timeoutMs);
                break;
            case UDPTimeoutFor::ReceiveFrom:
                mRecvFromTimeout = timeoutMs;
                setWriteReadTimeout(OpTimeout::Read, timeoutMs);
                break;
            default:
                throw Exception("Unknwon UDPTimeoutFor value");
            }
        }
    } // namespace base

    // Client namespace

    namespace client {
        ClientBase<IPProto::TCP>::ClientBase()
            : TCPSocketBase() {}

        ClientBase<IPProto::TCP>::ClientBase(platform::SocketT&& socket)
            : TCPSocketBase(std::move(socket)) {}

        ClientBase<IPProto::TCP>::ClientBase(ClientBase&& other)
            : TCPSocketBase(std::move(dynamic_cast<TCPSocketBase&>(other))) {}

        ClientBase<IPProto::TCP>& ClientBase<IPProto::TCP>::operator=(ClientBase&& other) {
            base::TCPSocketBase::operator=(std::move(dynamic_cast<base::TCPSocketBase&>(other)));
            return *this;
        }

        ClientBase<IPProto::TCP>::~ClientBase() {}

        IOResult ClientBase<IPProto::TCP>::send(const TransmitDataT* data, const std::size_t size) {
            return TCPSocketBase::send(data, size);
        }

        IOResult ClientBase<IPProto::TCP>::receive(TransmitDataT* data, const std::size_t maxSize) {
            return TCPSocketBase::receive(data, maxSize);
        }

        void ClientBase<IPProto::TCP>::close() { SocketBase::close(); }

        bool ClientBase<IPProto::TCP>::isSocketOpen() const { return SocketBase::isSocketOpen(); }

        void ClientBase<IPProto::TCP>::setTimeout(const TCPTimeoutFor timeoutFor, const Timeout timeoutMs) {
            TCPSocketBase::setTimeout(timeoutFor, timeoutMs);
        }

        Timeout ClientBase<IPProto::TCP>::getSendTimeout() const { return TCPSocketBase::getSendTimeout(); }

        Timeout ClientBase<IPProto::TCP>::getReceiveTimeout() const {
            return TCPSocketBase::getReceiveTimeout();
        }

        Client<IPProto::TCP>::Client()
            : ClientBase() {}

        Client<IPProto::TCP>::~Client() {}

        void Client<IPProto::TCP>::connect(const Address& address) { TCPSocketBase::connect(address); }

        bool Client<IPProto::TCP>::isSocketOpen() const { return SocketBase::isSocketOpen(); }

        void Client<IPProto::TCP>::setConnectTimeout(const Timeout timeoutMs) {
            ClientBase::setTimeout(TCPTimeoutFor::Connect, timeoutMs);
        }

        Timeout Client<IPProto::TCP>::getConnectTimeout() const { return ClientBase::getConnectTimeout(); }

        Client<IPProto::UDP>::Client()
            : UDPSocketBase() {}

        Client<IPProto::UDP>::Client(Client&& other)
            : UDPSocketBase(std::move(dynamic_cast<UDPSocketBase&>(other))) {}

        Client<IPProto::UDP>::~Client() {}

        void Client<IPProto::UDP>::bind(const Address& address) { SocketBase::bind(address); }

        IOResult Client<IPProto::UDP>::sendTo(const TransmitDataT* data,
                                              const std::size_t size,
                                              const Address& address) {
            return UDPSocketBase::sendTo(data, size, address);
        }

        IOResult
        Client<IPProto::UDP>::receiveFrom(TransmitDataT* data, const std::size_t maxSize, Address& address) {
            return UDPSocketBase::receiveFrom(data, maxSize, address);
        }

        bool Client<IPProto::UDP>::isSocketOpen() const { return SocketBase::isSocketOpen(); }

        void Client<IPProto::UDP>::close() { SocketBase::close(); }

        void Client<IPProto::UDP>::setTimeout(const UDPTimeoutFor timeoutFor, const Timeout timeoutMs) {
            UDPSocketBase::setTimeout(timeoutFor, timeoutMs);
        }

        Timeout Client<IPProto::UDP>::getSendToTimeout() const { return UDPSocketBase::getSendToTimeout(); }

        Timeout Client<IPProto::UDP>::getReceiveTimeout() const {
            return UDPSocketBase::getReceiveFromTimeout();
        }
    } // namespace client

    // Server namespace

    namespace server {
        Server<IPProto::TCP>::Server()
            : TCPSocketBase() {}

        Server<IPProto::TCP>::Server(Server&& other)
            : TCPSocketBase(std::move(dynamic_cast<TCPSocketBase&>(other))) {}

        Server<IPProto::TCP>::~Server() {}

        void Server<IPProto::TCP>::bind(const Address& address) { SocketBase::bind(address); }

        void Server<IPProto::TCP>::listen(const std::size_t backlogSize) const {
            TCPSocketBase::listen(backlogSize);
        }

        void Server<IPProto::TCP>::tryAccept(const OnAcceptFnc& onAccept, void* userArg) const {
            static std::function<void(platform::SocketT&&, Address&&, void*)> onAcceptInternal(
                [&](platform::SocketT&& socket, Address&& address, void* userArg) {
                    onAccept(
                        client::ClientBase<IPProto::TCP>(std::move(socket)), std::move(address), userArg);
                    socket = INVALID_SOCKET_DESCRIPTOR;
                });

            TCPSocketBase::tryAccept(onAcceptInternal, userArg);
        }

        bool Server<IPProto::TCP>::isSocketOpen() const { return SocketBase::isSocketOpen(); }

        void Server<IPProto::TCP>::close() { SocketBase::close(); }

        void Server<IPProto::TCP>::setAcceptTimeout(const Timeout timeoutMs) {
            TCPSocketBase::setTimeout(TCPTimeoutFor::Accept, timeoutMs);
        }

        Timeout Server<IPProto::TCP>::getAcceptTimeout() const { return TCPSocketBase::getAcceptTimeout(); }

        Server<IPProto::UDP>::Server()
            : Client() {}

        Server<IPProto::UDP>::Server(Server&& other)
            : Client(std::move(dynamic_cast<Client&>(other))) {}

        Server<IPProto::UDP>::~Server() {}

        void Server<IPProto::UDP>::close() { SocketBase::close(); }
    } // namespace server
} // namespace cppnetlib

// Overloaded operators

std::ostream& operator<<(std::ostream& stream, const cppnetlib::Ip& ip) {
    return (stream << ip.string());
}

std::ostream& operator<<(std::ostream& stream, const cppnetlib::Address& address) {
    return stream << address.ip().string() << ':' << address.port();
}