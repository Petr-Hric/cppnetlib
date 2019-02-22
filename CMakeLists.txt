cmake_minimum_required(VERSION 3.0)
project(cppnetlib VERSION 1.0.0 LANGUAGES C CXX)
set(platform ${CMAKE_SYSTEM_NAME})

if (${platform} STREQUAL "Linux")
	include("cmake/${platform}-compiler-config.txt")
elseif (${platform} STREQUAL "Windows")
    include("cmake/${platform}-compiler-config.txt")
endif()

add_library(cppnetlib STATIC
    src/cppnetlib.cpp
)

target_include_directories(cppnetlib
    PUBLIC include/
    PUBLIC include/cppnetlib/Endian/include/
    PUBLIC include/cppnetlib/Platform/include/
)

if (${platform} STREQUAL "Windows")
	target_link_libraries(cppnetlib
		PRIVATE ws2_32.lib
	)
endif()