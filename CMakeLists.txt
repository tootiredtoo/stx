cmake_minimum_required(VERSION 3.20)
project(STX LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# To avoid DOWNLOAD_EXTRACT_TIMESTAMP warning
cmake_policy(SET CMP0135 NEW)

# Compiler warnings
add_compile_options(-Wall -Wextra -Werror)

# For OpenSSL and GoogleTest libs
include(FetchContent)

# OpenSSL
FetchContent_Declare(
  openssl
  URL https://www.openssl.org/source/openssl-1.1.1w.tar.gz
)

FetchContent_MakeAvailable(openssl)

set(OPENSSL_INCLUDE_DIR ${openssl_SOURCE_DIR}/include)
set(OPENSSL_CRYPTO_LIBRARY ${openssl_BINARY_DIR}/libcrypto.a)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
)

# Source files
set(SRC_FILES
    src/common.cpp
    src/crypto.cpp
    src/files.cpp
    src/net.cpp
)

# Create static library from core files
add_library(stx_core STATIC ${SRC_FILES})

# Executables
add_executable(stx-rcv src/stx-rcv.cpp)
add_executable(stx-send src/stx-send.cpp)

# Link core lib to executables
target_link_libraries(stx-rcv PRIVATE stx_core)
target_link_libraries(stx-send PRIVATE stx_core)

# Tests 
include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/heads/main.zip
)

FetchContent_MakeAvailable(googletest)

enable_testing()
add_subdirectory(tests)

# Installation (optional)
install(TARGETS stx-rcv stx-send RUNTIME DESTINATION bin)
