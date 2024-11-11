cmake_minimum_required(VERSION 3.5.0)
project(server_epoll VERSION 0.1.0 LANGUAGES C CXX)

configure_file(conf/version.h.in ${CMAKE_SOURCE_DIR}/include/version.h)

include_directories(include)

# Specify the directory containing your source files
file(GLOB SOURCES "src/*.cpp")

find_package(OpenSSL REQUIRED)

add_executable(server_epoll ${SOURCES})

target_link_libraries(server_epoll PRIVATE ssl crypto)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20 -Wall -Wextra -Wpedantic") # TODO: append -s -Q --help=warning