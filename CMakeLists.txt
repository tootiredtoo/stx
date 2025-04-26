cmake_minimum_required(VERSION 3.20)
project(STX VERSION 0.1.0 LANGUAGES CXX)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Fix for MSVC & MinGW *WIN32*WINNT warning
add_compile_definitions(_WIN32_WINNT=0x0601)

# Avoid DOWNLOAD_EXTRACT_TIMESTAMP warning
cmake_policy(SET CMP0135 NEW)

# Compiler warnings
add_compile_options(-Wall -Wextra -Werror)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include FetchContent module
include(FetchContent)

# Define core library source files
set(STX_CORE_SOURCES
    src/crypto/crypto.cpp
    src/crypto/ssl_utils.cpp
    src/network/tcp_server.cpp
    src/protocols/protocol_client.cpp
    src/protocols/protocol_messages.cpp
    src/protocols/protocol_server.cpp
)

# Header files
set(STX_CORE_HEADERS
    include/crypto/crypto.hpp
    include/crypto/ssl_utils.hpp
    include/network/tcp_server.hpp
    include/protocols/protocol.hpp
)

# -------- Fetch ASIO --------
FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG asio-1-28-0
)
FetchContent_MakeAvailable(asio)

# -------- OpenSSL --------
find_package(OpenSSL 3.0 REQUIRED)

# Disable deprecated warnings as error for OpenSSL
# if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
#   add_compile_options(-Wno-error=deprecated-declarations)
# endif()

# -------- Threads --------
find_package(Threads REQUIRED)

# -------- Include Directories --------
include_directories(
  ${CMAKE_SOURCE_DIR}/include
  ${asio_SOURCE_DIR}/asio/include
)

# Define ASIO_STANDALONE to use the standalone version
add_compile_definitions(ASIO_STANDALONE)

# Create stx-core library
add_library(stx-core STATIC ${STX_CORE_SOURCES} ${STX_CORE_HEADERS})

# Link dependencies to stx-core
target_link_libraries(stx-core
  PUBLIC
  OpenSSL::SSL
  OpenSSL::Crypto
  Threads::Threads
)

# Create stx-send executable
add_executable(stx-send src/main/stx-send.cpp)
target_link_libraries(stx-send PRIVATE stx-core)

# Create stx-recv executable
add_executable(stx-recv src/main/stx-recv.cpp)
target_link_libraries(stx-recv PRIVATE stx-core)

# Platform-specific settings
if(WIN32)
  target_link_libraries(stx-core PUBLIC wsock32 ws2_32)
endif()

# # Install targets
# install(TARGETS stx-core stx-send stx-recv
#   RUNTIME DESTINATION bin
#   LIBRARY DESTINATION lib
#   ARCHIVE DESTINATION lib
# )

# install(FILES ${STX_CORE_HEADERS} DESTINATION include/stx)

# # Testing
# option(BUILD_TESTS "Build tests" OFF)
# if(BUILD_TESTS)
#     enable_testing()
#     add_subdirectory(tests)
# endif()