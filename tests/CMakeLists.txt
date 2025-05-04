# -------- OpenSSL --------
find_package(OpenSSL 3.0 REQUIRED)

# -------- Threads --------
find_package(Threads REQUIRED)

# -------- Fetch Asio --------
FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG asio-1-28-0
)
FetchContent_MakeAvailable(asio)

# Define test executables
set(TEST_EXECUTABLES
    crypto_tests
    protocol_messages_tests 
    protocol_client_tests
    protocol_server_tests
)

# Iterate over each test executable
foreach(test_name ${TEST_EXECUTABLES})
    # Add executable
    add_executable(${test_name} ${test_name}.cpp)
    
    # Link libraries
    target_link_libraries(${test_name}
        PRIVATE
        stx-core
        gtest
        gtest_main
        gmock
        Threads::Threads
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    
    # Include directories
    target_include_directories(${test_name}
        PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${asio_SOURCE_DIR}/asio/include
    )
    
    # Add test to CTest
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
