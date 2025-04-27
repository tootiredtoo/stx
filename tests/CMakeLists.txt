# -------- OpenSSL --------
find_package(OpenSSL 3.0 REQUIRED)

# -------- Threads --------
find_package(Threads REQUIRED)

# Define test executables
set(TEST_EXECUTABLES
    crypto_tests
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
    )
    
    # Add test to CTest
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()