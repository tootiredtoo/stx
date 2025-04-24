file(GLOB TEST_SOURCES *.cpp)

foreach(test_file ${TEST_SOURCES})
    get_filename_component(test_name ${test_file} NAME_WE)
    add_executable(${test_name} ${test_file})
    
    target_include_directories(${test_name} PRIVATE ${OPENSSL_INCLUDE_DIR})

    target_link_libraries(${test_name}
        PRIVATE
        stx_core
        gtest
        gmock
        gtest_main
        ${OPENSSL_CRYPTO_LIBRARY}
        ${OPENSSL_SSL_LIBRARY}
    )
    
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
