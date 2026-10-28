add_executable(unit_tests
    test_01_ip.cpp
    test_02_sba_http2.cpp
    test_03_sdp.cpp
    test_04_sip.cpp
    test_05_rtp.cpp
    test_06_diameter.cpp
    test_07_lte_nas.cpp
    test_08_nr_nas.cpp
)

target_link_libraries(unit_tests PRIVATE
    3gpp_core
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(unit_tests)
