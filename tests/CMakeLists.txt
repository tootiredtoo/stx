# Collect all test source files in current dir
file(GLOB TEST_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -mconsole")

foreach(test_file ${TEST_SOURCES})
    get_filename_component(test_name ${test_file} NAME_WE)

    add_executable(${test_name} ${test_file})

    target_include_directories(${test_name} 
        PRIVATE 
            ${CMAKE_SOURCE_DIR}/include
            ${OPENSSL_INCLUDE_DIR}
    )

    target_link_libraries(${test_name}
        PRIVATE
            stx_core
            gtest
            gmock
            gtest_main
            OpenSSL::SSL 
            OpenSSL::Crypto
            Threads::Threads
    )

    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
