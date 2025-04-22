file(GLOB TEST_SOURCES *.cpp)

foreach(test_file ${TEST_SOURCES})
    get_filename_component(test_name ${test_file} NAME_WE)
    add_executable(${test_name} ${test_file})
    
    target_link_libraries(${test_name}
        PRIVATE
        stx_core
        gtest
        gmock
        gtest_main
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
