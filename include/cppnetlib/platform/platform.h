#ifndef PLATFORM_H_
#define PLATFORM_H_

#include "cppnetlib/platform/platform_detect.h"

#if defined PLATFORM_WINDOWS

#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif

#ifndef NOMINMAX
#define NOMINMAX
#define NOMINMAX_NOT_DEFINED
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#define LEAN_AND_MEAN_NOT_DEFINED
#endif
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS_NOT_DEFINED
#endif

#include <WS2tcpip.h>
#include <WinSock2.h>

#ifndef NOMINMAX_NOT_DEFINED
#undef NOMINMAX
#endif
#ifndef LEAN_AND_MEAN_NOT_DEFINED
#undef WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS_NOT_DEFINED
#undef _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

// Mutex is used to protect Winsock init counter
#include <mutex>

#ifdef WINSOCK_VERSION
#define WS_VERSION WINSOCK_VERSION
#else
#define WS_VERSION MAKEWORD(2, 2)
#endif

#define SOCKET_OP_UNSUCCESSFUL SOCKET_ERROR
#define INVALID_SOCKET_DESCRIPTOR INVALID_SOCKET

#define CPPNL_NOACCESS WSAEACCES
#define CPPNL_DEST_ADDR_REQUIRED WSAEDESTADDRREQ
#define CPPNL_INVALID_ARGUMENT WSAEINVAL
#define CPPNL_DEST_ADDR_PROVIDED WSAEISCONN
#define CPPNL_NO_MEMORY WSA_NOT_ENOUGH_MEMORY
#define CPPNL_NOT_CONNECTED WSAENOTCONN
#define CPPNL_OPWOULDBLOCK WSAEWOULDBLOCK
#define CPPNL_CONNECTION_RESET WSAECONNRESET
#define CPPNL_CONNECTION_ABORT WSAECONNABORTED
#define CPPNL_CONNECTION_REFUSED WSAECONNREFUSED
#define CPPNL_NETWORK_UNREACHABLE WSAENETUNREACH
#define CPPNL_TIMEDOUT WSAETIMEDOUT
#define CPPNL_ALREADYCONNECTED WSAEISCONN
#define CPPNL_INVALID_SOCKET WSAENOTSOCK

#define CPPNL_SHUT_RD SD_RECEIVE
#define CPPNL_SHUT_WR SD_SEND
#define CPPNL_SHUT_RDWR SD_BOTH

namespace cppnetlib {
    namespace error {
        using NativeErrorCodeT = int;
    }

    namespace platform {
        using IoDataSizeT = int;
        using NetLibRetvT = int;
#ifdef _WS2DEF_
        using NativeFamilyT = ADDRESS_FAMILY;
#else
        using NativeFamilyT = short;
#endif
        using SockLenT = socklen_t;
        using NativeTransmitDataT = char;
    } // namespace platform
} // namespace cppnetlib

#elif defined PLATFORM_LINUX

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#define SOCKET_OP_UNSUCCESSFUL -1
#define INVALID_SOCKET_DESCRIPTOR -1

#define CPPNL_NOACCESS EACCES
#define CPPNL_DEST_ADDR_REQUIRED EDESTADDRREQ
#define CPPNL_INVALID_ARGUMENT EINVAL
#define CPPNL_DEST_ADDR_PROVIDED EISCONN
#define CPPNL_NO_MEMORY ENOMEM
#define CPPNL_NOT_CONNECTED ENOTCONN
#define CPPNL_OPWOULDBLOCK EWOULDBLOCK
#define CPPNL_CONNECTION_RESET ECONNRESET
#define CPPNL_CONNECTION_ABORT ECONNABORTED
#define CPPNL_CONNECTION_REFUSED ECONNREFUSED
#define CPPNL_NETWORK_UNREACHABLE ENETUNREACH
#define CPPNL_TIMEDOUT ETIMEDOUT
#define CPPNL_ALREADYCONNECTED EISCONN
#define CPPNL_INVALID_SOCKET ENOTSOCK

#define CPPNL_SHUT_RD SHUT_RD
#define CPPNL_SHUT_WR SHUT_WR
#define CPPNL_SHUT_RDWR SHUT_RDWR

namespace cppnetlib {
    namespace error {
        using NativeErrorCodeT = int;
    }

    namespace platform {
        using IoDataSizeT = std::size_t;
        using NetLibRetvT = int;
        using NativeFamilyT = int;
        using SockLenT = socklen_t;
        using NativeTransmitDataT = char;
    } // namespace platform
} // namespace cppnetlib

#else

#error Unsupported platform!

#endif

namespace cppnetlib {
    namespace error {
        std::string toString(const IResult value);
        std::string toString(const OResult value);
        std::string toString(const NativeErrorCodeT value);
    } // namespace error

    namespace platform {
        inline error::NativeErrorCodeT nativeErrorCode();
    }
} // namespace cppnetlib

#endif