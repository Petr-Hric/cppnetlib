#include "cppnetlib/cppnetlib.h"

#include "cppnetlib/endian/endian.h"
#include "cppnetlib/platform/platform.h"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <memory>

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

    static constexpr int direction_lut[] = {
        CPPNL_SHUT_WR
        , CPPNL_SHUT_RD
        , CPPNL_SHUT_RDWR
    };

    inline int encodeDirection(const Direction direction) {
        assert(static_cast<std::size_t>(direction) < (sizeof(direction_lut) / sizeof(decltype(direction_lut))));
        return direction_lut[static_cast<std::size_t>(direction)];
    }

    namespace exception {
        class UnknownAddressFamilyException : public Exception {
        public:
            explicit UnknownAddressFamilyException(const std::string& function)
                : Exception(function + " -> Unknown address family") {}
        };

        class ExceptionWithSystemErrorMessage : public Exception {
        public:
            ExceptionWithSystemErrorMessage(const std::string& function, const std::string& message)
                : Exception(function + " -> " + message + " [" + std::to_string(platform::nativeErrorCode()) +
                " | Native message - " + error::toString(platform::nativeErrorCode()) + "]") {}
        };

        class ConnectionTimeoutException : public Exception {
        public:
            explicit ConnectionTimeoutException(const std::string& function)
                : Exception(function + " -> Connection timeout") {}
        };
    } // namespace exception

    namespace helpers {
        platform::SockLenT toSockLen(const Address& address);
    }
    sockaddr createSockAddr(const Address& address);

    // Platform dependent definitions/declarations

    namespace error {
        #if defined PLATFORM_WINDOWS

        std::string toString(const NativeErrorCodeT value) {
            std::string output;
            char* message = nullptr;
            if(0 == FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr,
                value,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPSTR)&message,
                0,
                nullptr) {
                    return "";
                }

            output = message;

            LocalFree(message);

            return output;
        }

        #elif defined PLATFORM_LINUX

        std::string toString(const NativeErrorCodeT value) { return std::strerror(value); }

        #else

        #error Unsupported platform!

        #endif
    }

    namespace platform {
        #if defined PLATFORM_WINDOWS

        class Winsock {
        public:
            Winsock() {
                if(WSAStartup(WS_VERSION, &wsad) != 0) {
                    throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                        "Could not initialize WinSock");
                }
            }

            ~Winsock() {
                try {
                    if(WSACleanup() != 0) {
                        throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                            "Could not deinitialize WinSock");
                    }
                } catch(...) {
                }
            }

        private:
            WSAData wsad;
        };

        static Winsock winsock;

        inline error::NativeErrorCodeT nativeErrorCode() { return WSAGetLastError(); }

        bool nativeSocketCloseWrapper(const platform::SocketT socket) {
            return ::closesocket(socket) == SOCKET_OP_SUCCESSFUL;
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
            switch(addressFamily) {
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

            if(WSAAddressToStringA(reinterpret_cast<sockaddr*>(&sockAddrStorage),
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

            if(WSAStringToAddressA(
                scrCopy, addressFamily, nullptr, (struct sockaddr*)&sockAddrStorage, &size) == 0) {
                switch(addressFamily) {
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

        void nativeSetSockOpt(const platform::SocketT socket, const int level, const int optName, const void* opt, const int optLen) {
            assert(opt != nullptr);
            assert(optLen > 0);
            if(setsockopt(socket, level, optName, reinterpret_cast<const char*>(opt), optLen) != 0) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                    "Could not perform getsockopt");
            }
        }

        void nativeGetSockOpt(const platform::SocketT socket, const int level, const int optName, void* opt, int* optLen) {
            assert(opt != nullptr);
            assert(optLen != nullptr);
            if(getsockopt(socket, level, optName, reinterpret_cast<char*>(opt), optLen) != 0) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                    "Could not perform getsockopt");
            }
        }

        #elif defined PLATFORM_LINUX

        inline error::NativeErrorCodeT nativeErrorCode() { return errno; }

        bool nativeSocketCloseWrapper(const platform::SocketT socket) {
            return ::close(socket) == SOCKET_OP_SUCCESSFUL;
        }

        bool nativeSetBlocked(platform::SocketT socket, const bool blocked) {
            int flags = fcntl(socket, F_GETFL, 0);
            if(flags == -1) {
                return false;
            }

            flags = blocked ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);

            if(fcntl(socket, F_SETFL, flags) == -1) {
                return false;
            }
            return true;
        }

        void nativeInetPton(const NativeFamilyT addressFamily, const char* src, void* dst) {
            assert(src != nullptr);
            assert(dst != nullptr);
            const int retv = inet_pton(addressFamily, src, dst);

            if(retv == 0) {
                throw Exception(FUNC_NAME +
                    ": Could not convert address to network format, because the input string is "
                    "not valid address");
            } else if(retv == -1) {
                throw Exception(
                    FUNC_NAME +
                    ": Could not convert address to network format, because the IP version is unknown");
            } else if(retv != 1) {
                throw exception::ExceptionWithSystemErrorMessage(
                    FUNC_NAME, "Could not convert address to network format");
            } // else: Operation successful
        }

        inline void nativeInetNtop(const NativeFamilyT addressFamily,
            const void* src,
            char* dst,
            const std::size_t dstMaxSize) {
            if(inet_ntop(addressFamily, src, dst, dstMaxSize) == nullptr) {
                throw exception::ExceptionWithSystemErrorMessage(
                    FUNC_NAME, "Could not convert network address to human readable format");
            }
        }

        void nativeSetSockOpt(const platform::SocketT socket, const int level, const int optName, const void* opt, const int optLen) {
            assert(opt != nullptr);
            assert(optLen > 0);

            static_assert(sizeof(int) == sizeof(socklen_t), "Incompatible type size");

            if(setsockopt(socket, level, optName, opt, static_cast<socklen_t>(optLen)) != 0) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                    "Could not perform setsockopt");
            }
        }

        void nativeGetSockOpt(const platform::SocketT socket, const int level, const int optName, void* opt, int* optLen) {
            assert(opt != nullptr);
            assert(optLen != nullptr);

            static_assert(sizeof(int) == sizeof(socklen_t), "Incompatible type size");

            if(getsockopt(socket, level, optName, opt, reinterpret_cast<socklen_t*>(optLen)) != 0) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                    "Could not perform getsockopt");
            }
        }

        #else

        #error Unsupported platform!

        #endif

        // Common

        SocketT nativeSocketOpen(const NativeFamilyT addressFamily, const int ipProtocol) {
            int type = 0;
            switch(ipProtocol) {
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
            if(socket == INVALID_SOCKET_DESCRIPTOR) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not open socket");
            }
            return socket;
        }

        void nativeSocketShutdown(const platform::SocketT socket, const Direction direction) {
            if(::shutdown(socket, encodeDirection(direction)) != 0) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not shutdown socket");
            }
        }

        void nativeSocketClose(platform::SocketT& socket) {
            if(!nativeSocketCloseWrapper(socket)) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not close socket");
            }
            socket = INVALID_SOCKET_DESCRIPTOR;
        }

        error::ConnectResult nativeConnect(platform::SocketT& socket, const Address& address) {
            const sockaddr sockAddr = createSockAddr(address);
            if(::connect(socket, &sockAddr, helpers::toSockLen(address)) != SOCKET_OP_SUCCESSFUL) {
                const int errorCode = nativeErrorCode();
                switch(errorCode) {
                    case CPPNL_ALREADYCONNECTED:
                        return error::ConnectResult::AlreadyConnected;
                    case CPPNL_OPWOULDBLOCK:
                        return error::ConnectResult::OpWouldBlock;
                    case CPPNL_NETWORK_UNREACHABLE:
                        return error::ConnectResult::NetworkUnreachable;
                    case CPPNL_TIMEDOUT:
                        return error::ConnectResult::OperationTimedOut;
                    case CPPNL_CONNECTION_REFUSED:
                        return error::ConnectResult::Refused;
                    default:
                        throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                            "Could not connect to the server");
                }
            }
            return error::ConnectResult::Successful;
        }
    }

    // Helpers

    namespace helpers {
        platform::NativeFamilyT toNativeFamily(const IPVer ipVersion) {
            switch(ipVersion) {
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
            switch(ipVersion) {
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
            switch(addressFamily) {
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
        if(ip.empty()) {
            mIpStr.clear();
        } else {
            if(isIpV4Addr(ip)) {
                mIpVer = IPVer::IPv4;
            } else if(isIpV6Addr(ip)) {
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
        } catch(const exception::UnknownAddressFamilyException&) {
            return false;
        }
        return true;
    }

    bool Ip::isIpV6Addr(const std::string& ip) {
        struct sockaddr_in6 sa;
        try {
            platform::nativeInetPton(AF_INET6, ip.c_str(), &sa);
        } catch(const exception::UnknownAddressFamilyException&) {
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

        switch(address.ip().version()) {
            case IPVer::IPv4:
            {
                sockaddr_in& ipv4addr = reinterpret_cast<sockaddr_in&>(sockAddr);
                ipv4addr.sin_family = helpers::toNativeFamily(address.ip().version());
                ipv4addr.sin_port = Endian::convertNativeTo(address.port(), Endian::Type::Big);
                platform::nativeInetPton(helpers::toNativeFamily(address.ip().version()),
                    address.ip().string().c_str(),
                    &ipv4addr.sin_addr);
                break;
            }
            case IPVer::IPv6:
            {
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

        switch(sockAddr.sa_family) {
            case AF_INET:
            {
                const sockaddr_in& ipv4addr = reinterpret_cast<const sockaddr_in&>(sockAddr);
                port = Endian::convertToNative(ipv4addr.sin_port, Endian::Type::Big);
                platform::nativeInetNtop(AF_INET, &ipv4addr.sin_addr, ipBuffer, sizeof(ipBuffer));
                break;
            }
            case AF_INET6:
            {
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
        std::string toString(const IResult value) {
            assert(static_cast<std::size_t>(value) < 8);
            static const std::string errorMessage[] = {
                "OpWouldBlock"
                , "ConnectionRefused"
                , "NoMemoryAvailable"
                , "NotConnected"
                , "SocketPassedIsNotValid"
                , "ConnectionAbort"
                , "Disconnected"
                , "Successful"
            };

            return errorMessage[static_cast<size_t>(value)];
        }

        std::string toString(const OResult value) {
            assert(static_cast<std::size_t>(value) < 11);
            static const std::string errorMessage[] = {
                  "NoAccess"
                , "OpWouldBlock"
                , "ConnectionReset"
                , "NoDestinationAddressProvidedInNonConnectionMode"
                , "InvalidArgument"
                , "DestinationAddressProvidedInConnectionMode"
                , "NoMemoryAvailable"
                , "NotConnected"
                , "SocketPassedIsNotValid"
                , "ConnectionAbort"
                , "Successful"
            };

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
                if(this->isSocketOpen()) {
                    this->close();
                }
            } catch(...) {
            }
        }

        SocketBase& SocketBase::operator=(SocketBase&& other) {
            mSocket = std::exchange(other.mSocket, INVALID_SOCKET_DESCRIPTOR);
            mBlocking = other.mBlocking;
            return *this;
        }

        void SocketBase::close() {
            if(!isSocketOpen()) {
                throw Exception(FUNC_NAME + ": Could not close socket, because the socket is already closed");
            }
            platform::nativeSocketClose(mSocket);
        }

        void SocketBase::bind(const Address& address, const bool allowReuse) {
            if(!isSocketOpen()) {
                openSocket(address.ip().version());
            }

            if(allowReuse) {
                const int opt = 1;
                const int optLen = sizeof(opt);
                platform::nativeSetSockOpt(mSocket, SOL_SOCKET, SO_REUSEADDR, &opt, optLen);
            }

            const sockaddr sockAddr = createSockAddr(address);
            const platform::NetLibRetvT retv = ::bind(mSocket, &sockAddr, helpers::toSockLen(address));
            if(retv == SOCKET_OP_UNSUCCESSFUL) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                    "Could not bind address to socket");
            } else if(retv != SOCKET_OP_SUCCESSFUL) {
                throw Exception(FUNC_NAME + ": Unknown error occured");
            } // else: Operation successful
        }

        void SocketBase::shutdown(const Direction direction) const {
            platform::nativeSocketShutdown(mSocket, direction);
        }

        void SocketBase::setBlocked(const bool blocked) {
            if(!isSocketOpen()) {
                throw Exception(FUNC_NAME + ": Socket is not open");
            }

            if(!platform::nativeSetBlocked(mSocket, blocked)) {
                throw exception::ExceptionWithSystemErrorMessage(
                    FUNC_NAME, "Could not set blocking/non-blocking socket property");
            }

            mBlocking = blocked;
        }

        bool SocketBase::blocked() const { return mBlocking; }

        bool SocketBase::isSocketOpen() const { return mSocket != INVALID_SOCKET_DESCRIPTOR; }

        class SocketBaseAccessor {
        public:
            static void setFdSet(std::deque<SocketBase*>& set, ::fd_set& fdSet, platform::SocketT& maxFd) {
                FD_ZERO(&fdSet);

                for(const auto it : set) {
                    assert(it != nullptr);

                    FD_SET((*it).mSocket, &fdSet);

                    if((*it).mSocket > maxFd) {
                        maxFd = (*it).mSocket;
                    }
                }
            }

            static void filterFdSet(std::deque<SocketBase*>& set, const ::fd_set& fdSet) {
                for(std::deque<SocketBase*>::iterator it = set.begin(); it != set.end();) {
                    assert(*it != nullptr);

                    if(FD_ISSET((*it)->mSocket, &fdSet) == 0) {
                        it = set.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

            // static error::OResult error() {
            //         //#define ETIMEDOUT    110 /* Connection timed out */
            //         //#define ECONNREFUSED 111 /* Connection refused */
            //         //#define EHOSTDOWN    112 /* Host is down */
            //         //#define EHOSTUNREACH 113 /* No route to host */
            //         //#define EALREADY     114 /* Operation already in progress */
            //         //#define EINPROGRESS  115 /* Operation now in progress */
            // 
            //     error::ConnectResult::OperationTimedOut;
            //     error::ConnectResult::Refused;
            //     //
            //     error::ConnectResult::NetworkUnreachable;
            //     error::ConnectResult::AlreadyConnected;
            //     error::ConnectResult::NetworkDown;
            // }
        };

        bool SocketBase::wait(std::deque<SocketBase*>* const read
            , std::deque<SocketBase*>* const write
            , std::deque<SocketBase*>* const error
            , const BaseTimeUnit& timeout) {
            platform::SocketT maxFd = 0;

            std::unique_ptr<fd_set> fdReadSet;
            if(read) {
                fdReadSet.reset(new fd_set);
                SocketBaseAccessor::setFdSet(*read, *fdReadSet, maxFd);
            }

            std::unique_ptr<fd_set> fdWriteSet;
            if(write) {
                fdWriteSet.reset(new fd_set);
                SocketBaseAccessor::setFdSet(*write, *fdWriteSet, maxFd);
            }

            std::unique_ptr<fd_set> fdErrorSet;
            if(error) {
                fdErrorSet.reset(new fd_set);
                SocketBaseAccessor::setFdSet(*error, *fdErrorSet, maxFd);
            }

            const BaseTimeUnit::rep sec = timeout.count() / static_cast<BaseTimeUnit::rep>(1000000);
            const BaseTimeUnit::rep uSec = timeout.count() % static_cast<BaseTimeUnit::rep>(1000000);

            assert(sec <= std::numeric_limits<long>::max());
            assert(uSec <= std::numeric_limits<long>::max());

            timeval tv = {
                static_cast<long>(sec)
                , static_cast<long>(uSec)
            };

            const int selectRetv = select(static_cast<int>(maxFd + 1), fdReadSet.get(), fdWriteSet.get(), fdErrorSet.get(), &tv);
            if(selectRetv == 0) {
                return false;
            } else if(selectRetv == SOCKET_OP_UNSUCCESSFUL) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not perform select");
            } else {
                if(read != nullptr) {
                    SocketBaseAccessor::filterFdSet(*read, *fdReadSet);
                }

                if(write != nullptr) {
                    SocketBaseAccessor::filterFdSet(*write, *fdWriteSet);
                }

                if(error != nullptr) {
                    SocketBaseAccessor::filterFdSet(*error, *fdErrorSet);
                }
            }
            return true;
        }

        bool SocketBase::rwTimeout(const OpTimeout selectTimeoutFor, const BaseTimeUnit& timeout) const {
            if(!isSocketOpen()) {
                throw Exception(FUNC_NAME +
                    ": Could not perform connect/accept timeout, because the socket is not open");
            }

            fd_set fdSet;
            fd_set fdErrorSet;
            fd_set* fdWritePtr = nullptr;
            fd_set* fdReadPtr = nullptr;

            switch(selectTimeoutFor) {
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

            FD_ZERO(&fdErrorSet);
            FD_SET(mSocket, &fdErrorSet);

            const BaseTimeUnit::rep sec = timeout.count() / static_cast<BaseTimeUnit::rep>(1000000);
            const BaseTimeUnit::rep uSec = timeout.count() % static_cast<BaseTimeUnit::rep>(1000000);

            assert(sec <= std::numeric_limits<long>::max());
            assert(uSec <= std::numeric_limits<long>::max());

            timeval tv;
            tv.tv_sec = static_cast<long>(sec);
            tv.tv_usec = static_cast<long>(uSec);

            const int selectRetv = select(static_cast<int>(mSocket + 1), fdReadPtr, fdWritePtr, &fdErrorSet, &tv);
            if(selectRetv == 0) {
                return true;
            } else if(selectRetv == SOCKET_OP_UNSUCCESSFUL) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not perform select");
            } else {
                if(FD_ISSET(mSocket, &fdErrorSet) != 0) {
                    int err = 0;
                    int optLen = sizeof(err);

                    platform::nativeGetSockOpt(mSocket, SOL_SOCKET, SO_ERROR, &err, &optLen);

                    return true;
                }

                if(FD_ISSET(mSocket, &fdSet) == 0) {
                    throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                        "Unexpected behavior");
                }
            }

            return false;
        }

        void SocketBase::setWriteReadTimeout(const OpTimeout opTimeoutFor, const BaseTimeUnit& timeout) {
            if(!isSocketOpen()) {
                throw Exception(FUNC_NAME +
                    ": Could not set write/read timeout, because the socket is not open");
            }

            #if defined PLATFORM_WINDOWS
            const Millis::rep tmp = TimeCast<Millis>(timeout).count();

            assert(tmp <= std::numeric_limits<int>::max());

            const int millis = static_cast<int>(tmp);

            switch(opTimeoutFor) {
                case OpTimeout::Write:
                    platform::nativeSetSockOpt(mSocket,
                        SOL_SOCKET,
                        SO_SNDTIMEO,
                        &millis,
                        sizeof(millis));

                    break;
                case OpTimeout::Read:
                    platform::nativeSetSockOpt(mSocket,
                        SOL_SOCKET,
                        SO_RCVTIMEO,
                        &timeout,
                        sizeof(timeout));
                    break;
                default:
                    throw Exception("Unknown OpTimeout value");
            }
            #elif defined PLATFORM_LINUX
            const int micros = TimeCast<Micros>(timeout).count();

            const timeval tv = {
                micros / 1000000
                , micros % 1000000
            };

            switch(opTimeoutFor) {
                case OpTimeout::Write:
                    platform::nativeSetSockOpt(mSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                    break;
                case OpTimeout::Read:
                    platform::nativeSetSockOpt(mSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                    break;
                default:
                    throw Exception("Unknown OpTimeout value");
            }
            #else
            #error Unsupported platform
            #endif
        }

        IResult SocketBase::processIResult() {
            const error::NativeErrorCodeT errorCode = platform::nativeErrorCode();
            switch(errorCode) {
                case CPPNL_OPWOULDBLOCK:
                    return error::makeError<std::size_t, error::IResult>(
                        error::IResult::OpWouldBlock);
                case CPPNL_CONNECTION_RESET:
                    close();

                    return error::makeError<std::size_t, error::IResult>(
                        error::IResult::ConnectionReset);
                case CPPNL_CONNECTION_REFUSED:
                    close();

                    return error::makeError<std::size_t, error::IResult>(
                        error::IResult::ConnectionRefused);
                case CPPNL_INVALID_ARGUMENT:
                    return error::makeError<std::size_t, error::IResult>(
                        error::IResult::InvalidArgument);
                case CPPNL_NO_MEMORY:
                    return error::makeError<std::size_t, error::IResult>(
                        error::IResult::NoMemoryAvailable);
                case CPPNL_NOT_CONNECTED:
                    return error::makeError<std::size_t, error::IResult>(
                        error::IResult::NotConnected);
                case CPPNL_INVALID_SOCKET:
                    return error::makeError<std::size_t, error::IResult>(
                        error::IResult::InvalidArgument);
                case CPPNL_CONNECTION_ABORT:
                    close();

                    return error::makeError<std::size_t, error::IResult>(
                        error::IResult::ConnectionAbort);
                default:
                    throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not send data");
            }
        }

        OResult SocketBase::processOResult() {
            const error::NativeErrorCodeT errorCode = platform::nativeErrorCode();
            switch(errorCode) {
                case CPPNL_NOACCESS:
                    return error::makeError<std::size_t, error::OResult>(
                        error::OResult::NoAccess);
                case CPPNL_OPWOULDBLOCK:
                    return error::makeError<std::size_t, error::OResult>(
                        error::OResult::OpWouldBlock);
                case CPPNL_CONNECTION_RESET:
                    close();

                    return error::makeError<std::size_t, error::OResult>(
                        error::OResult::ConnectionReset);
                case CPPNL_DEST_ADDR_REQUIRED:
                    return error::makeError<std::size_t, error::OResult>(
                        error::OResult::NoDestinationAddressProvidedInNonConnectionMode);
                case CPPNL_INVALID_ARGUMENT:
                    return error::makeError<std::size_t, error::OResult>(
                        error::OResult::InvalidArgument);
                case CPPNL_DEST_ADDR_PROVIDED:
                    return error::makeError<std::size_t, error::OResult>(
                        error::OResult::DestinationAddressProvidedInConnectionMode);
                case CPPNL_NO_MEMORY:
                    return error::makeError<std::size_t, error::OResult>(
                        error::OResult::NoMemoryAvailable);
                case CPPNL_NOT_CONNECTED:
                    return error::makeError<std::size_t, error::OResult>(
                        error::OResult::NotConnected);
                case CPPNL_INVALID_SOCKET:
                    return error::makeError<std::size_t, error::OResult>(
                        error::OResult::InvalidArgument);
                case CPPNL_CONNECTION_ABORT:
                    close();

                    return error::makeError<std::size_t, error::OResult>(
                        error::OResult::ConnectionAbort);
                default:
                    throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not send data");
            }
        }

        TCPSocketBase::TCPSocketBase()
            : SocketBase()
            , mSendTimeout(TimeCast<BaseTimeUnit>(Millis(DEFAULT_TCP_SEND_TIMEOUT)))
            , mRecvTimeout(TimeCast<BaseTimeUnit>(Millis(DEFAULT_TCP_RECV_TIMEOUT)))
            , mConnectTimeout(TimeCast<BaseTimeUnit>(Millis(DEFAULT_TCP_CONNECT_TIMEOUT)))
            , mAcceptTimeout(TimeCast<BaseTimeUnit>(Millis(DEFAULT_TCP_ACCEPT_TIMEOUT)))
            , mNagle(true) {}

        TCPSocketBase::TCPSocketBase(TCPSocketBase&& other)
            : SocketBase(std::move(other))
            , mSendTimeout(std::move(other.mSendTimeout))
            , mRecvTimeout(std::move(other.mRecvTimeout))
            , mConnectTimeout(std::move(other.mConnectTimeout))
            , mAcceptTimeout(std::move(other.mAcceptTimeout))
            , mNagle(std::move(other.mNagle)) {}

        TCPSocketBase::TCPSocketBase(platform::SocketT&& socket)
            : SocketBase(std::exchange(socket, INVALID_SOCKET_DESCRIPTOR))
            , mSendTimeout(TimeCast<BaseTimeUnit>(Millis(DEFAULT_TCP_SEND_TIMEOUT)))
            , mRecvTimeout(TimeCast<BaseTimeUnit>(Millis(DEFAULT_TCP_RECV_TIMEOUT)))
            , mConnectTimeout(TimeCast<BaseTimeUnit>(Millis(DEFAULT_TCP_CONNECT_TIMEOUT)))
            , mAcceptTimeout(TimeCast<BaseTimeUnit>(Millis(DEFAULT_TCP_ACCEPT_TIMEOUT)))
            , mNagle(nagle_(mSocket)) {}

        TCPSocketBase& TCPSocketBase::operator=(TCPSocketBase&& other) {
            mSendTimeout = std::move(other.mSendTimeout);
            mRecvTimeout = std::move(other.mRecvTimeout);
            mConnectTimeout = std::move(other.mConnectTimeout);
            mAcceptTimeout = std::move(other.mAcceptTimeout);
            mNagle = std::move(other.mNagle);

            SocketBase::operator=(std::move(static_cast<base::SocketBase&>(other)));

            return *this;
        }

        TCPSocketBase::~TCPSocketBase() {}

        void TCPSocketBase::openSocket(const IPVer ipVer) {
            if(isSocketOpen()) {
                throw Exception(FUNC_NAME + ": Could not open socket, the socket is already open");
            }
            mSocket = platform::nativeSocketOpen(helpers::toNativeFamily(ipVer), IPPROTO_TCP);

            setBlocked(false);
        }

        void TCPSocketBase::nagle_(const platform::SocketT socket, const bool enable) {
            const int flag = enable ? 1 : 0;
            platform::nativeSetSockOpt(socket
                , IPPROTO_TCP
                , TCP_NODELAY
                , &flag
                , sizeof(flag));
        }

        bool TCPSocketBase::nagle_(const platform::SocketT socket) {
            int flag = 0;
            int optlen = sizeof(flag);

            platform::nativeGetSockOpt(socket
                , IPPROTO_TCP
                , TCP_NODELAY
                , &flag
                , &optlen);

            return flag ? false : true;
        }

        ConnectResult TCPSocketBase::connect(const Address& address) {
            if(!isSocketOpen()) {
                openSocket(address.ip().version());
            }

            const error::ConnectResult errorCode = platform::nativeConnect(mSocket, address);
            switch(errorCode) {
                case error::ConnectResult::Successful:
                    return true;
                case error::ConnectResult::OpWouldBlock:
                    if(getConnectTimeout().count() > 0 && rwTimeout(OpTimeout::Write, getConnectTimeout())) {
                        return error::makeError<bool, error::ConnectResult>(
                            error::ConnectResult::OperationTimedOut);
                    } else {
                        if(!waitWrite(*this, mConnectTimeout)) {
                            return error::makeError<bool, error::ConnectResult>(
                                error::ConnectResult::OpWouldBlock);
                        } else {
                            return true;
                        }
                    }
                    break;
                default:
                    return error::makeError<bool, error::ConnectResult>(
                        errorCode);
            }
        }

        void TCPSocketBase::listen(const std::size_t backlogSize) const {
            if(!isSocketOpen()) {
                throw Exception(FUNC_NAME +
                    ": Could not open socket for listening, because the socket is not open");
            }

            if(::listen(mSocket,
                static_cast<int>(std::min<std::size_t>(std::numeric_limits<int>::max(),
                backlogSize))) != SOCKET_OP_SUCCESSFUL) {
                throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME,
                    "Could not open socket for listening");
            }
        }

        void TCPSocketBase::tryAccept(
            const std::function<void(platform::SocketT&&, Address&&, void*)>& onAccept,
            void* userArg) const {
            sockaddr addr = {};

            if(rwTimeout(OpTimeout::Read, mAcceptTimeout)) {
                return;
            }

            platform::SockLenT sockLen = helpers::toSockLen(IPVer::IPv6 /*Max sockaddr size*/);
            platform::SocketT socket = ::accept(mSocket, &addr, &sockLen);
            if(socket == INVALID_SOCKET_DESCRIPTOR) {
                if(platform::nativeErrorCode() != CPPNL_OPWOULDBLOCK) {
                    throw exception::ExceptionWithSystemErrorMessage(FUNC_NAME, "Could not accept client");
                } else {
                    return;
                }
            }

            onAccept(std::move(socket), createAddress(addr), userArg);
        }

        OResult TCPSocketBase::send(const TransmitDataT* data, const std::size_t size) {
            assert(data != nullptr);
            if(!isSocketOpen()) {
                throw Exception(FUNC_NAME + ": Could not send data, because the socket is not open");
            }

            if(rwTimeout(OpTimeout::Write, mSendTimeout)) {
                return error::makeError<std::size_t, error::OResult>(
                    error::OResult::OpWouldBlock);
            }

            const platform::NetLibRetvT retv =
                ::send(mSocket,
                reinterpret_cast<const platform::NativeTransmitDataT*>(data),
                static_cast<platform::IoDataSizeT>(
                std::min<std::size_t>(static_cast<std::size_t>(cMaxTransmitionUnitSize), size)),
                0);
            if(retv == SOCKET_OP_UNSUCCESSFUL) {
                return processOResult();
            }

            assert(retv >= 0);

            return static_cast<std::size_t>(retv);
        }

        IResult TCPSocketBase::receive(TransmitDataT* data, const std::size_t maxSize) {
            assert(data != nullptr);
            if(!isSocketOpen()) {
                throw Exception(FUNC_NAME + ": Could not receive data, because the socket is not open");
            }

            if(rwTimeout(OpTimeout::Read, mRecvTimeout)) {
                return error::makeError<std::size_t, error::IResult>(
                    error::IResult::OpWouldBlock);
            }

            const platform::NetLibRetvT retv =
                ::recv(mSocket,
                reinterpret_cast<platform::NativeTransmitDataT*>(data),
                static_cast<platform::IoDataSizeT>(
                std::min<std::size_t>(static_cast<std::size_t>(cMaxTransmitionUnitSize), maxSize)),
                0);

            if(retv == SOCKET_OP_UNSUCCESSFUL) {
                return processIResult();
            } else if(retv == 0) {
                return error::makeError<std::size_t, error::IResult>(
                    error::IResult::Disconnected);
            }

            assert(retv > 0);

            return static_cast<std::size_t>(retv);
        }

        void TCPSocketBase::nagle(const bool enable) {
            mNagle = enable;

            if(!isSocketOpen()) {
                return;
            }

            nagle_(mSocket, enable);
        }

        bool TCPSocketBase::nagle() const {
            return mNagle;
        }

        UDPSocketBase::UDPSocketBase()
            : SocketBase()
            , mSendToTimeout(DEFAULT_UDP_SENDTO_TIMEOUT)
            , mRecvFromTimeout(DEFAULT_UDP_RECVFROM_TIMEOUT) {}

        UDPSocketBase::UDPSocketBase(UDPSocketBase&& other)
            : SocketBase(std::move(other))
            , mSendToTimeout(std::move(other.mSendToTimeout))
            , mRecvFromTimeout(std::move(other.mRecvFromTimeout)) {}

        UDPSocketBase::~UDPSocketBase() {}

        void UDPSocketBase::openSocket(const IPVer ipVer) {
            if(isSocketOpen()) {
                throw Exception(FUNC_NAME + ": Could not open socket, the socket is already open");
            }
            mSocket = platform::nativeSocketOpen(helpers::toNativeFamily(ipVer), IPPROTO_UDP);

            setBlocked(false);
        }

        OResult
            UDPSocketBase::sendTo(const TransmitDataT* data, const std::size_t size, const Address& address) {
            assert(data != nullptr);

            if(!isSocketOpen()) {
                openSocket(address.ip().version());
            }

            if(rwTimeout(OpTimeout::Write, mSendToTimeout)) {
                return error::makeError<std::size_t, error::OResult>(
                    error::OResult::OpWouldBlock);
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

            if(retv == SOCKET_OP_UNSUCCESSFUL) {
                return processOResult();
            }

            assert(retv > 0);

            return static_cast<std::size_t>(retv);
        }

        IResult
            UDPSocketBase::receiveFrom(TransmitDataT* data, const std::size_t maxSize, Address& address) {
            assert(data != nullptr);

            if(!isSocketOpen()) {
                openSocket(address.ip().version());
            }

            if(rwTimeout(OpTimeout::Read, mRecvFromTimeout)) {
                return error::makeError<std::size_t, error::IResult>(
                    error::IResult::OpWouldBlock);
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

            if(retv == SOCKET_OP_UNSUCCESSFUL) {
                return processIResult();
            }

            address = createAddress(sockAddr);

            assert(sockLen == helpers::toSockLen(address));
            assert(retv > 0);

            return static_cast<std::size_t>(retv);
        }
    } // namespace base

    // Client namespace

    namespace client {
        ClientBase<IPProto::TCP>::ClientBase()
            : TCPSocketBase() {}

        ClientBase<IPProto::TCP>::ClientBase(platform::SocketT&& socket)
            : TCPSocketBase(std::exchange(socket, INVALID_SOCKET_DESCRIPTOR)) {}

        ClientBase<IPProto::TCP>::ClientBase(ClientBase&& other)
            : TCPSocketBase(std::move(other)) {}

        ClientBase<IPProto::TCP>& ClientBase<IPProto::TCP>::operator=(ClientBase&& other) {
            base::TCPSocketBase::operator=(std::move(other));
            return *this;
        }

        ClientBase<IPProto::TCP>::~ClientBase() {}

        OResult ClientBase<IPProto::TCP>::send(const TransmitDataT* data, const std::size_t size) {
            return TCPSocketBase::send(data, size);
        }

        IResult ClientBase<IPProto::TCP>::receive(TransmitDataT* data, const std::size_t maxSize) {
            return TCPSocketBase::receive(data, maxSize);
        }

        void ClientBase<IPProto::TCP>::close() { SocketBase::close(); }

        bool ClientBase<IPProto::TCP>::isSocketOpen() const { return SocketBase::isSocketOpen(); }

        const BaseTimeUnit& ClientBase<IPProto::TCP>::getSendTimeout() const { return TCPSocketBase::getSendTimeout(); }

        const BaseTimeUnit& ClientBase<IPProto::TCP>::getReceiveTimeout() const {
            return TCPSocketBase::getReceiveTimeout();
        }

        Client<IPProto::TCP>::Client()
            : ClientBase() {}

        Client<IPProto::TCP>::~Client() {}

        ConnectResult Client<IPProto::TCP>::connect(const Address& address) {
            return TCPSocketBase::connect(address);
        }

        bool Client<IPProto::TCP>::isSocketOpen() const { return SocketBase::isSocketOpen(); }

        const BaseTimeUnit& Client<IPProto::TCP>::getConnectTimeout() const { return ClientBase::getConnectTimeout(); }

        Client<IPProto::UDP>::Client()
            : UDPSocketBase() {}

        Client<IPProto::UDP>::Client(Client&& other)
            : UDPSocketBase(std::move(other)) {}

        Client<IPProto::UDP>::~Client() {}

        void Client<IPProto::UDP>::bind(const Address& address, const bool allowReuse) { SocketBase::bind(address, allowReuse); }

        OResult Client<IPProto::UDP>::sendTo(const TransmitDataT* data,
            const std::size_t size,
            const Address& address) {
            return UDPSocketBase::sendTo(data, size, address);
        }

        IResult
            Client<IPProto::UDP>::receiveFrom(TransmitDataT* data, const std::size_t maxSize, Address& address) {
            return UDPSocketBase::receiveFrom(data, maxSize, address);
        }

        bool Client<IPProto::UDP>::isSocketOpen() const { return SocketBase::isSocketOpen(); }

        void Client<IPProto::UDP>::close() { SocketBase::close(); }

        const BaseTimeUnit& Client<IPProto::UDP>::getSendToTimeout() const { return UDPSocketBase::getSendToTimeout(); }

        const BaseTimeUnit& Client<IPProto::UDP>::getReceiveTimeout() const {
            return UDPSocketBase::getReceiveFromTimeout();
        }
    } // namespace client

    // Server namespace

    namespace server {
        Server<IPProto::TCP>::Server()
            : TCPSocketBase() {}

        Server<IPProto::TCP>::Server(Server&& other)
            : TCPSocketBase(std::move(other)) {}

        Server<IPProto::TCP>::~Server() {}

        void Server<IPProto::TCP>::bind(const Address& address, const bool allowReuse) {
            SocketBase::bind(address, allowReuse);

            nagle(nagle());
        }

        void Server<IPProto::TCP>::listen(const std::size_t backlogSize) const {
            TCPSocketBase::listen(backlogSize);
        }

        void Server<IPProto::TCP>::tryAccept(const OnAcceptFnc& onAccept, void* userArg) const {
            TCPSocketBase::tryAccept(
                [onAccept](platform::SocketT&& socket, Address&& address, void* userArg) {
                onAccept(
                    client::ClientBase<IPProto::TCP>(
                    std::exchange(socket, INVALID_SOCKET_DESCRIPTOR))
                    , std::move(address), userArg);
            }
            , userArg);
        }

        bool Server<IPProto::TCP>::isSocketOpen() const { return SocketBase::isSocketOpen(); }

        void Server<IPProto::TCP>::close() { SocketBase::close(); }

        const BaseTimeUnit& Server<IPProto::TCP>::getAcceptTimeout() const { return TCPSocketBase::getAcceptTimeout(); }

        Server<IPProto::UDP>::Server()
            : Client() {}

        Server<IPProto::UDP>::Server(Server&& other)
            : Client(std::move(other)) {}

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