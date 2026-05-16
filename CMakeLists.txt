cmake_minimum_required(VERSION 3.10)
project(ntop C)
set(CMAKE_C_STANDARD 99)
add_compile_options(-Wall -Wextra)

option(WITH_NCURSES "Enable ncurses TUI"            ON)
option(WITH_PCAP    "Enable libpcap packet capture" ON)
option(WITH_WIFI    "Enable WiFi scanning"          ON)

set(SOURCES
    src/main.c
    src/tui.c
    src/views/iface.c
    src/views/conns.c
    src/views/wifi.c
    src/views/packets.c
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND SOURCES src/platform/linux.c)
    add_definitions(-DPLATFORM_LINUX)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND SOURCES src/platform/bsd.c)
    add_definitions(-DPLATFORM_BSD)
elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD|OpenBSD|NetBSD")
    list(APPEND SOURCES src/platform/bsd.c)
    add_definitions(-DPLATFORM_BSD)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND SOURCES src/platform/win32.c)
    add_definitions(-DPLATFORM_WIN32)
else()
    list(APPEND SOURCES src/platform/stub.c)
    add_definitions(-DPLATFORM_STUB)
endif()

add_executable(ntop ${SOURCES})
target_include_directories(ntop PRIVATE include src)

if(WITH_NCURSES)
    find_package(Curses REQUIRED)
    target_compile_definitions(ntop PRIVATE WITH_NCURSES)
    target_link_libraries(ntop PRIVATE ${CURSES_LIBRARIES})
    target_include_directories(ntop PRIVATE ${CURSES_INCLUDE_DIRS})
endif()

if(WITH_PCAP)
    find_library(PCAP_LIB pcap)
    if(PCAP_LIB)
        target_compile_definitions(ntop PRIVATE WITH_PCAP)
        target_link_libraries(ntop PRIVATE ${PCAP_LIB})
    else()
        message(WARNING "libpcap not found — packet capture disabled")
    endif()
endif()

if(WITH_WIFI)
    target_compile_definitions(ntop PRIVATE WITH_WIFI)
endif()

install(TARGETS ntop DESTINATION bin)
