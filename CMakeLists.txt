cmake_minimum_required(VERSION 3.20)
project(STX LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warnings
add_compile_options(-Wall -Wextra -Werror)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

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

# Link OpenSSL to the core library
target_link_libraries(stx_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)

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
