#ifndef CPPNETLIB_PLATFORM_DETECT_H_
#define CPPNETLIB_PLATFORM_DETECT_H_

#if defined _WIN32 || defined _WIN64
#define PLATFORM_WINDOWS

#if defined _WIN32 && !defined _WIN64
#define PLATFORM_WINDOWS32
#elif defined _WIN64
#define PLATFORM_WINDOWS64
#endif

#elif defined __linux__ || defined linux || defined __gnu_linux__
#define PLATFORM_LINUX
#else
#error Unsupported platform!
#endif

#endif