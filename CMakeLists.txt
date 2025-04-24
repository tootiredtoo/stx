cmake_minimum_required(VERSION 3.20)
project(STX LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Fix for MSVC & MinGW _WIN32_WINNT warning
add_compile_definitions(_WIN32_WINNT=0x0601)

# Avoid DOWNLOAD_EXTRACT_TIMESTAMP warning
cmake_policy(SET CMP0135 NEW)

# Compiler warnings
add_compile_options(-Wall -Wextra -Werror)

# -------- Fetch ASIO --------
include(FetchContent)
FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG asio-1-28-0
)
FetchContent_MakeAvailable(asio)

# -------- OpenSSL --------
find_package(OpenSSL REQUIRED)

# -------- Threads --------
find_package(Threads REQUIRED)

# -------- Include Directories --------
include_directories(
  ${CMAKE_SOURCE_DIR}/include
  ${asio_SOURCE_DIR}/asio/include
)

# -------- Source Files --------
set(SRC_FILES
  src/common.cpp
  src/files.cpp
  src/network/tcp_server.cpp
  src/crypto/ssl_utils.cpp
)

# -------- Core Static Library --------
add_library(stx_core STATIC ${SRC_FILES})

target_link_libraries(stx_core
  PUBLIC
    OpenSSL::SSL 
    OpenSSL::Crypto
    Threads::Threads
    ws2_32
)

if (WIN32)
    target_link_libraries(stx_core PRIVATE mswsock)
endif()

# -------- Settings for console applications --------
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -mconsole")

# -------- Executables --------
# add_executable(stx-send src/main/stx-send.cpp)
# add_executable(stx-recv src/main/stx-recv.cpp)
add_executable(stx-server main.cpp)  # dev/test server

# Link core lib to executables
# target_link_libraries(stx-send PRIVATE stx_core)
# target_link_libraries(stx-recv PRIVATE stx_core)
target_link_libraries(stx-server PRIVATE stx_core)

# Explicitly set the console subsystem
target_link_options(stx-server PRIVATE -mconsole)
# target_link_options(stx-send PRIVATE -mconsole)
# target_link_options(stx-recv PRIVATE -mconsole)

# -------- Tests (GoogleTest) --------
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/heads/main.zip
)
FetchContent_MakeAvailable(googletest)

enable_testing()
add_subdirectory(tests)

# -------- Installation --------
# install(TARGETS stx-send stx-recv RUNTIME DESTINATION bin)
