#ifndef SOCKETBASE_H_
#define SOCKETBASE_H_

#include <string>
#include <cstdint>
#include <functional>

#define FUNC_NAME std::string(__func__)

namespace cppnetlib {
    // Common

    enum class IPVer : uint32_t {
        IPv4
        , IPv6
        , Unknown
    };

    enum class IPProto : uint32_t {
        TCP
        , UDP
    };

    using IpT = std::string;
    using PortT = uint16_t;
    using TransmittedDataSizeT = std::size_t;
    using TransmitDataT = uint8_t;

    // Exception

    class Exception {
    public:
        Exception(std::string message);

        const std::string& message() const;

    private:
        const std::string mMessage;
    };

    // Error namespace

    namespace error {
        enum class ReceiveError {
            ErrorOccured = 1
            , OpWouldBlock
            , GracefullyDisconnected
        };

        template <typename ValueT, typename ErrorT>
        class ExpectedValue {
        public:
            ExpectedValue(ValueT&& value) :
                mValue(std::move(value)) {}

            ExpectedValue& operator =(const ValueT& value) {
                mValue = value;
            }

            bool hasError() const {
                return mHasError;
            }

            ValueT value() {
                if (hasError()) {
                    throw Exception(FUNC_NAME + ": There is no value");
                }
                return mValue;
            }

            const ErrorT& error() {
                if (!hasError()) {
                    throw Exception(FUNC_NAME + ": There is no error");
                }
                return mError;
            }

            template <typename OtherValueT, typename OtherErrorT>
            friend ExpectedValue<OtherValueT, OtherErrorT> makeError(const OtherErrorT& error);

        private:
            ExpectedValue() = default;

            bool mHasError = false;
            ValueT mValue;
            ErrorT mError;
        };

        template <typename ValueT, typename ErrorT>
        ExpectedValue<ValueT, ErrorT> makeError(const ErrorT& error) {
            ExpectedValue<ValueT, ErrorT> expected;
            expected.mHasError = true;
            expected.mError = error;
            return expected;
        }
    }

    // Platform namespace

    namespace platform {
#if defined _WIN64

        using SocketT = unsigned long long;

#elif defined _WIN32

        using SocketT = unsigned long;

#elif defined __linux__

        using SocketT = int;

#else

#error Unsupported platform!

#endif
    }

    // Address forward declaration

    class Address;

    // Base namespace

    namespace base {
        class SocketBase {
        public:
            SocketBase(const IPVer ipVersion);

            SocketBase(const IPVer ipVersion, platform::SocketT socket);

            SocketBase(SocketBase&& other);

            SocketBase& operator =(SocketBase&& other);

            SocketBase(const SocketBase&) = delete;
            SocketBase& operator =(const SocketBase&) = delete;

            virtual ~SocketBase();

            virtual void open() = 0;

            void close(const bool socketCreatedByUser = true);

            void bind(const Address& address);

            void setBlocked(const bool blocked);

            bool isOpen() const;

            IPVer ipVersion() const;

        private:
            IPVer mIPVersion;

        protected:
            platform::SocketT mSocket;
        };

        class TCPSocketBase : public SocketBase {
        public:
            TCPSocketBase(const IPVer ipVersion);

            TCPSocketBase(const IPVer ipVersion, platform::SocketT&& socket);

            virtual ~TCPSocketBase();

            virtual void open() override;

            void connect(const Address& address);

            void listen(const std::size_t backlogSize);

            void tryAccept(std::function<void(platform::SocketT&&, Address&&)>& onAccept) const;

            std::size_t send(const TransmitDataT* data, const std::size_t size) const;

            error::ExpectedValue<std::size_t, error::ReceiveError> receive(TransmitDataT* data, const std::size_t maxSize) const;
        };

        class UDPSocketBase : public SocketBase {
        public:
            UDPSocketBase(const IPVer ipVersion);

            UDPSocketBase(const IPVer ipVersion, platform::SocketT&& socket);

            virtual ~UDPSocketBase();

            virtual void open() override;

            std::size_t sendTo(const TransmitDataT* data, const std::size_t size, const Address& address) const;

            error::ExpectedValue<std::size_t, error::ReceiveError> receiveFrom(TransmitDataT* data, const std::size_t maxSize, Address& address) const;
        };
    }

    // Client namespace

    namespace client {
        // Client Base

        template <IPProto IPProtocol>
        class ClientBase;

        template <>
        class ClientBase<IPProto::TCP> : protected base::TCPSocketBase {
        public:
            ClientBase(const IPVer ipVersion);

            ClientBase(const IPVer ipVersion, platform::SocketT&& socket);

            virtual ~ClientBase();

            void setBlocked(const bool blocked);

            std::size_t send(const TransmitDataT* data, const std::size_t size) const;

            error::ExpectedValue<std::size_t, error::ReceiveError> receive(TransmitDataT* data, const std::size_t maxSize) const;
        };

        // Client

        template <IPProto IPProtocol>
        class Client;

        template<>
        class Client<IPProto::TCP> : public ClientBase<IPProto::TCP> {
        public:
            Client(const IPVer ipVersion);

            virtual ~Client();

            void connect(const Address& address);
        };

        template<>
        class Client<IPProto::UDP> : private base::UDPSocketBase {
        public:
            Client(const IPVer ipVersion);

            virtual ~Client();

            void setBlocked(const bool blocked);

            void bind(const Address& address);

            std::size_t sendTo(const TransmitDataT* data, const std::size_t size, const Address& address) const;

            error::ExpectedValue<std::size_t, error::ReceiveError> receiveFrom(TransmitDataT* data, const std::size_t maxSize, Address& address) const;
        };
    }

    // Server namespace

    namespace server {
        // Server

        template <IPProto IPProtocol>
        class Server;

        template<>
        class Server<IPProto::TCP> : private base::TCPSocketBase {
        public:
            Server(const IPVer ipVersion);

            virtual ~Server();

            void setBlocked(const bool blocked);

            void bind(const Address& address);

            void listen(const std::size_t backlogSize);

            void tryAccept(std::function<void(client::ClientBase<IPProto::TCP>&&, Address&& address)>& onAccept) const;
        };

        template<>
        class Server<IPProto::UDP> : public client::Client<IPProto::UDP> {
        public:
            Server(const IPVer ipVersion);

            virtual ~Server();
        };
    }

    // Address

    class Address {
    public:
        Address() = default;

        Address(const Address& other);

        Address(Address&& other);

        Address(const IPVer ipVersion, const IpT& ip, const PortT port);

        Address& operator = (const Address& other);

        Address& operator = (Address&& other);

        bool operator ==(const Address& other) const;

        bool operator !=(const Address& other) const;

        const IpT& ip() const;

        PortT port() const;

        IPVer ipVersion() const;

    private:
        IpT mIp = "";
        PortT mPort = 0U;
        IPVer mIpVersion = IPVer::Unknown;

        friend class base::SocketBase;
        friend class base::TCPSocketBase;
        friend class base::UDPSocketBase;
    };
}

#endif