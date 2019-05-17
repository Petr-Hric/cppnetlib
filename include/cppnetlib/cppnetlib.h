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
        enum class IOReturnValue { OpWouldBlock, GracefullyDisconnected };

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

            const ErrorT& error() const{
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

            virtual ~SocketBase();

            SocketBase& operator=(SocketBase&& other);

            SocketBase(const SocketBase&) = delete;
            SocketBase& operator=(const SocketBase&) = delete;

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

            TCPSocketBase(platform::SocketT&& socket);

            virtual ~TCPSocketBase();

            void connect(const Address& address);

            void listen(const std::size_t backlogSize);

            void tryAccept(std::function<void(platform::SocketT&&, Address&&)>& onAccept);

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

            bool connectAcceptTimeout(const OpTimeout opTimeoutFor, const Timeout timeout);

            Timeout mSendTimeout;
            Timeout mRecvTimeout;
            Timeout mConnectTimeout;
            Timeout mAcceptTimeout;
        };

        class UDPSocketBase : public SocketBase {
        public:
            UDPSocketBase();

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
            ClientBase();

            ClientBase(platform::SocketT&& socket);

            virtual ~ClientBase();

            error::ExpectedValue<std::size_t, error::IOReturnValue> send(const TransmitDataT* data,
                                                                         const std::size_t size);

            error::ExpectedValue<std::size_t, error::IOReturnValue> receive(TransmitDataT* data,
                                                                            const std::size_t maxSize);

            bool isSocketOpen() const;

            void setTimeout(const TCPTimeoutFor timeoutFor, const Timeout timeoutMs);

            Timeout getSendTimeout() const;

            Timeout getReceiveTimeout() const;
        };

        // Client

        template <IPProto IPProtocol>
        class Client;

        template <>
        class Client<IPProto::TCP> : public ClientBase<IPProto::TCP> {
        public:
            Client();

            virtual ~Client();

            void connect(const Address& address);

            bool isSocketOpen() const;

            void close();

            void setConnectTimeout(const Timeout timeoutMs);

            Timeout getConnectTimeout() const;
        };

        template <>
        class Client<IPProto::UDP> : protected base::UDPSocketBase {
        public:
            Client();

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

            virtual ~Server();

            void bind(const Address& address);

            void listen(const std::size_t backlogSize);

            void
            tryAccept(std::function<void(client::ClientBase<IPProto::TCP>&&, Address&& address)>& onAccept);

            bool isSocketOpen() const;

            void close();

            void setAcceptTimeout(const Timeout timeoutMs);

            Timeout getAcceptTimeout() const;
        };

        template <>
        class Server<IPProto::UDP> : public client::Client<IPProto::UDP> {
        public:
            Server();

            virtual ~Server();

            bool isSocketOpen() const;

            void close();
        };
    } // namespace server

    // Ip

    class Ip {
    public:
        Ip();

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

    private:
        bool isIpV4Addr(const std::string& ip);

        bool isIpV6Addr(const std::string& ip);

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

#endif