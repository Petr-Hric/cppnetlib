#ifndef SOCKETBASE_H_
#define SOCKETBASE_H_

#include "Platform/platformDetect.h"

#include <cstdint>
#include <functional>
#include <string>

#define FUNC_NAME std::string(__func__)

namespace cppnetlib {
    // Common

    enum class IPVer : uint32_t { IPv4, IPv6, Unknown };

    enum class IPProto : uint32_t { TCP, UDP };

    enum class TCPTimeoutFor { Send, Recieve, Connect, Accept };

    enum class UDPTimeoutFor { SendTo, ReceiveFrom };

    using PortT = uint16_t;
    using TransmittedDataSizeT = std::size_t;
    using TransmitDataT = uint8_t;
    using Timeout = uint32_t;

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
        enum class IOReturnValue { Successful, OpWouldBlock, GracefullyDisconnected };

        template <typename ValueT, typename ErrorT>
        class ExpectedValue {
        public:
            ExpectedValue() = default;

            ExpectedValue(ValueT&& value)
                : mValue(std::move(value)) {}

            ExpectedValue& operator=(const ValueT& value) { mValue = value; }

            bool hasError() const { return mHasError; }

            ValueT value() const {
                if (hasError()) {
                    throw Exception(FUNC_NAME + ": There is no value");
                }
                return mValue;
            }

            const ErrorT& error() const {
                if (!hasError()) {
                    throw Exception(FUNC_NAME + ": There is no error");
                }
                return mError;
            }

            template <typename OtherValueT, typename OtherErrorT>
            friend ExpectedValue<OtherValueT, OtherErrorT> makeError(const OtherErrorT& error);

        private:
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
    } // namespace error

    // Platform namespace

    namespace platform {
#if defined PLATFORM_WINDOWS64

        using SocketT = unsigned long long;

#elif defined PLATFORM_WINDOWS32

        using SocketT = unsigned long;

#elif defined PLATFORM_LINUX

        using SocketT = int;

#else

#error Unsupported platform!

#endif
    } // namespace platform

    // Address forward declaration

    class Address;

    // Base namespace

    namespace base {
        class SocketBase {
        public:
            SocketBase();

            SocketBase(platform::SocketT socket);

            SocketBase(SocketBase&& other);

            SocketBase(const SocketBase&) = delete;
            SocketBase& operator=(const SocketBase&) = delete;

            virtual ~SocketBase();

            SocketBase& operator=(SocketBase&& other);

            void close(const bool socketCreatedByUser = true);

            void bind(const Address& address);

            bool blocked() const;

            bool isSocketOpen() const;

        private:
            bool mBlocking;

        protected:
            enum class OpTimeout { Write, Read };

            void setBlocked(const bool blocked);

            void setWriteReadTimeout(const OpTimeout opTimeoutFor, const Timeout timeout);

            platform::SocketT mSocket;

        protected:
            virtual void openSocket(const IPVer ipVer) = 0;

            friend class BlockGuard;
        };

        class TCPSocketBase : public SocketBase {
        public:
            TCPSocketBase();

            TCPSocketBase(TCPSocketBase&& other);

            TCPSocketBase(const TCPSocketBase&) = delete;
            TCPSocketBase& operator=(const TCPSocketBase&) = delete;

            TCPSocketBase(platform::SocketT&& socket);

            virtual ~TCPSocketBase();

            void connect(const Address& address);

            void listen(const std::size_t backlogSize) const;

            void tryAccept(const std::function<void(platform::SocketT&&, Address&&)>& onAccept) const;

            error::ExpectedValue<std::size_t, error::IOReturnValue> send(const TransmitDataT* data,
                                                                         const std::size_t size);

            error::ExpectedValue<std::size_t, error::IOReturnValue> receive(TransmitDataT* data,
                                                                            const std::size_t maxSize);

            void setTimeout(const TCPTimeoutFor timeoutFor, const Timeout timeoutMs);

            Timeout getSendTimeout() const { return mSendTimeout; }

            Timeout getReceiveTimeout() const { return mRecvTimeout; }

            Timeout getConnectTimeout() const { return mConnectTimeout; }

            Timeout getAcceptTimeout() const { return mAcceptTimeout; }

        private:
            void openSocket(const IPVer ipVer) override;

            bool connectAcceptTimeout(const OpTimeout opTimeoutFor, const Timeout timeout) const;

            Timeout mSendTimeout;
            Timeout mRecvTimeout;
            Timeout mConnectTimeout;
            Timeout mAcceptTimeout;
        };

        class UDPSocketBase : public SocketBase {
        public:
            UDPSocketBase();

            UDPSocketBase(const UDPSocketBase&) = delete;
            UDPSocketBase& operator=(const UDPSocketBase&) = delete;

            virtual ~UDPSocketBase();

            error::ExpectedValue<std::size_t, error::IOReturnValue>
            sendTo(const TransmitDataT* data, const std::size_t size, const Address& address);

            error::ExpectedValue<std::size_t, error::IOReturnValue>
            receiveFrom(TransmitDataT* data, const std::size_t maxSize, Address& address);

            void setTimeout(const UDPTimeoutFor timeoutFor, const Timeout timeoutMs);

            Timeout getSendToTimeout() const { return mSendToTimeout; }

            Timeout getReceiveFromTimeout() const { return mRecvFromTimeout; }

        private:
            void openSocket(const IPVer ipVer) override;

            Timeout mSendToTimeout;
            Timeout mRecvFromTimeout;
        };
    } // namespace base

    // Client namespace

    namespace client {
        // Client Base

        template <IPProto IPProtocol>
        class ClientBase;

        template <>
        class ClientBase<IPProto::TCP> : protected base::TCPSocketBase {
        public:
            ClientBase(ClientBase&& other);

            ClientBase(platform::SocketT&& socket);

            ClientBase(const ClientBase&) = delete;
            ClientBase& operator=(const ClientBase&) = delete;

            virtual ~ClientBase();

            error::ExpectedValue<std::size_t, error::IOReturnValue> send(const TransmitDataT* data,
                                                                         const std::size_t size);

            error::ExpectedValue<std::size_t, error::IOReturnValue> receive(TransmitDataT* data,
                                                                            const std::size_t maxSize);

            bool isSocketOpen() const;

            void close();

            void setTimeout(const TCPTimeoutFor timeoutFor, const Timeout timeoutMs);

            Timeout getSendTimeout() const;

            Timeout getReceiveTimeout() const;

        protected:
            ClientBase();
        };

        // Client

        template <IPProto IPProtocol>
        class Client;

        template <>
        class Client<IPProto::TCP> : public ClientBase<IPProto::TCP> {
        public:
            Client();

            Client(const Client&) = delete;
            Client& operator=(const Client&) = delete;

            virtual ~Client();

            void connect(const Address& address);

            bool isSocketOpen() const;

            void setConnectTimeout(const Timeout timeoutMs);

            Timeout getConnectTimeout() const;
        };

        template <>
        class Client<IPProto::UDP> : protected base::UDPSocketBase {
        public:
            Client();

            Client(const Client&) = delete;
            Client& operator=(const Client&) = delete;

            virtual ~Client();

            void bind(const Address& address);

            error::ExpectedValue<std::size_t, error::IOReturnValue>
            sendTo(const TransmitDataT* data, const std::size_t size, const Address& address);

            error::ExpectedValue<std::size_t, error::IOReturnValue>
            receiveFrom(TransmitDataT* data, const std::size_t maxSize, Address& address);

            bool isSocketOpen() const;

            void close();

            void setTimeout(const UDPTimeoutFor timeoutFor, const Timeout timeoutMs);

            Timeout getSendToTimeout() const;

            Timeout getReceiveTimeout() const;
        };
    } // namespace client

    // Server namespace

    namespace server {
        // Server

        template <IPProto IPProtocol>
        class Server;

        template <>
        class Server<IPProto::TCP> : private base::TCPSocketBase {
        public:
            Server();

            Server(const Server&) = delete;
            Server& operator=(const Server&) = delete;

            virtual ~Server();

            void bind(const Address& address);

            void listen(const std::size_t backlogSize) const;

            void tryAccept(const std::function<void(client::ClientBase<IPProto::TCP>&&, Address&& address)>&
                               onAccept) const;

            bool isSocketOpen() const;

            void close();

            void setAcceptTimeout(const Timeout timeoutMs);

            Timeout getAcceptTimeout() const;
        };

        template <>
        class Server<IPProto::UDP> : public client::Client<IPProto::UDP> {
        public:
            Server();

            Server(const Server&) = delete;
            Server& operator=(const Server&) = delete;

            virtual ~Server();

            bool isSocketOpen() const;

            void close();
        };
    } // namespace server

    // Ip

    class Ip {
    public:
        Ip();

        Ip(const Ip& other);

        Ip(Ip&& other);

        Ip(const char* ip);

        Ip(const std::string& ip);

        const std::string& string() const;

        IPVer version() const;

        bool operator==(const Ip& other) const;

        bool operator!=(const Ip& other) const;

        Ip& operator=(const Ip& other);

        Ip& operator=(Ip&& other);

        Ip& operator=(const char* ip);

        Ip& operator=(const std::string& ip);

        bool operator<(const Ip& other) const;

    private:
        static bool isIpV4Addr(const std::string& ip);

        static bool isIpV6Addr(const std::string& ip);

        IPVer mIpVer;
        std::string mIpStr;
    };

    // Address

    class Address {
    public:
        Address() = default;

        Address(const Address& other);

        Address(Address&& other);

        Address(const Ip& ip, const PortT port);

        Address& operator=(const Address& other);

        Address& operator=(Address&& other);

        bool operator==(const Address& other) const;

        bool operator!=(const Address& other) const;

        bool operator<(const Address& other) const;

        const Ip& ip() const;

        PortT port() const;

    private:
        Ip mIp = "";
        PortT mPort = 0U;

        friend class base::SocketBase;
        friend class base::TCPSocketBase;
        friend class base::UDPSocketBase;
    };
} // namespace cppnetlib

// Overloaded operators

std::ostream& operator<<(std::ostream& stream, const cppnetlib::Ip& ip);

#endif