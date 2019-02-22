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

    using IpT = std::string;
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
            SocketBase(const IPVer ipVersion);

            SocketBase(const IPVer ipVersion, platform::SocketT socket);

            SocketBase(SocketBase&& other);

            SocketBase& operator=(SocketBase&& other);

            SocketBase(const SocketBase&) = delete;
            SocketBase& operator=(const SocketBase&) = delete;

            virtual ~SocketBase();

            virtual void openSocket() = 0;

            void closeSocket(const bool socketCreatedByUser = true);

            void bind(const Address& address);

            bool blocked() const;

            bool isSocketOpen() const;

            IPVer ipVersion() const;

        private:
            IPVer mIPVersion;
            bool mBlocked;

        protected:
            enum class OpTimeout { Write, Read };

            void setBlocked(const bool blocked);

            void setWriteReadTimeout(const OpTimeout opTimeoutFor, const Timeout timeout);

            platform::SocketT mSocket;

            friend class BlockGuard;
        };

        class TCPSocketBase : public SocketBase {
        public:
            TCPSocketBase(const IPVer ipVersion);

            TCPSocketBase(const IPVer ipVersion, platform::SocketT&& socket);

            virtual ~TCPSocketBase();

            void connect(const Address& address);

            void listen(const std::size_t backlogSize);

            void tryAccept(std::function<void(platform::SocketT&&, Address&&)>& onAccept);

            error::ExpectedValue<std::size_t, error::IOReturnValue> send(const TransmitDataT* data,
                                                                         const std::size_t size);

            error::ExpectedValue<std::size_t, error::IOReturnValue> receive(TransmitDataT* data,
                                                                            const std::size_t maxSize);

            virtual void openSocket() override;

            void setTimeout(const TCPTimeoutFor timeoutFor, const Timeout timeoutMs);

            Timeout getSendTimeout() const { return mSendTimeout; }

            Timeout getReceiveTimeout() const { return mRecvTimeout; }

            Timeout getConnectTimeout() const { return mConnectTimeout; }

            Timeout getAcceptTimeout() const { return mAcceptTimeout; }

        private:
            bool connectAcceptTimeout(const OpTimeout opTimeoutFor, const Timeout timeout);

            Timeout mSendTimeout;
            Timeout mRecvTimeout;
            Timeout mConnectTimeout;
            Timeout mAcceptTimeout;
        };

        class UDPSocketBase : public SocketBase {
        public:
            UDPSocketBase(const IPVer ipVersion);

            virtual ~UDPSocketBase();

            virtual void openSocket() override;

            error::ExpectedValue<std::size_t, error::IOReturnValue>
            sendTo(const TransmitDataT* data, const std::size_t size, const Address& address);

            error::ExpectedValue<std::size_t, error::IOReturnValue>
            receiveFrom(TransmitDataT* data, const std::size_t maxSize, Address& address);

            void setTimeout(const UDPTimeoutFor timeoutFor, const Timeout timeoutMs);

            Timeout getSendToTimeout() const { return mSendToTimeout; }

            Timeout getReceiveFromTimeout() const { return mRecvFromTimeout; }

        private:
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
            ClientBase(const IPVer ipVersion);

            ClientBase(const IPVer ipVersion, platform::SocketT&& socket);

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
            Client(const IPVer ipVersion);

            virtual ~Client();

            void connect(const Address& address);

            bool isSocketOpen() const;

            void closeSocket();

            void openSocket();

            void setConnectTimeout(const Timeout timeoutMs);

            Timeout getConnectTimeout() const;
        };

        template <>
        class Client<IPProto::UDP> : protected base::UDPSocketBase {
        public:
            Client(const IPVer ipVersion);

            virtual ~Client();

            void bind(const Address& address);

            error::ExpectedValue<std::size_t, error::IOReturnValue>
            sendTo(const TransmitDataT* data, const std::size_t size, const Address& address);

            error::ExpectedValue<std::size_t, error::IOReturnValue>
            receiveFrom(TransmitDataT* data, const std::size_t maxSize, Address& address);

            bool isSocketOpen() const;

            void closeSocket();

            void openSocket();

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
            Server(const IPVer ipVersion);

            virtual ~Server();

            void bind(const Address& address);

            void listen(const std::size_t backlogSize);

            void
            tryAccept(std::function<void(client::ClientBase<IPProto::TCP>&&, Address&& address)>& onAccept);

            bool isSocketOpen() const;

            void closeSocket();

            void openSocket();

            void setAcceptTimeout(const Timeout timeoutMs);

            Timeout getAcceptTimeout() const;
        };

        template <>
        class Server<IPProto::UDP> : public client::Client<IPProto::UDP> {
        public:
            Server(const IPVer ipVersion);

            bool isSocketOpen() const;

            void closeSocket();

            void openSocket();

            virtual ~Server();
        };
    } // namespace server

    // Address

    class Address {
    public:
        Address() = default;

        Address(const Address& other);

        Address(Address&& other);

        Address(const IPVer ipVersion, const IpT& ip, const PortT port);

        Address& operator=(const Address& other);

        Address& operator=(Address&& other);

        bool operator==(const Address& other) const;

        bool operator!=(const Address& other) const;

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
} // namespace cppnetlib

#endif