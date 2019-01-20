#ifndef PLATFORM_H_
#define PLATFORM_H_

#if defined _WIN32

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

#include <WinSock2.h>
#include <WS2tcpip.h>

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

#define CPPNL_OPWOULDBLOCK WSAEWOULDBLOCK

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
        using SockLenT = int;
        using NativeTransmitDataT = char;
    }
}

#elif defined __linux__

#include <cerrno>
#include <arpa/inet.h>

#define SOCKET_OP_UNSUCCESSFUL -1
#define INVALID_SOCKET_DESCRIPTOR -1

#define CPPNL_OPWOULDBLOCK EWOULDBLOCK

namespace cppnetlib {
    namespace error {
        using NativeErrorCodeT = int;
    }

    namespace platform {
        using IoDataSizeT = std::size_t;
        using NetLibRetvT = int;
        using NativeFamilyT = int;
        using SockLenT = std::size_t;
        using NativeTransmitDataT = char;
    }
}

#else

#error Unsupported platform!

#endif

namespace cppnetlib {
    namespace error {
        std::string toString(const IOReturnValue value);
        std::string toString(const NativeErrorCodeT value);
    }

    namespace platform {
        inline error::NativeErrorCodeT nativeErrorCode();
    }
}

#endif