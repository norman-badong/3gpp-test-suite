add_executable(unit_tests
    test_01_ip.cpp
)

target_link_libraries(unit_tests PRIVATE
    3gpp_core
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(unit_tests)
