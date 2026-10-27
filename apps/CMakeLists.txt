add_executable(demo_01_ip_echo
    demo_01_ip_echo.cpp
)
target_link_libraries(demo_01_ip_echo PRIVATE
    3gpp_core
)

add_executable(demo_02_sba_http2
    demo_02_sba_http2.cpp
)
target_link_libraries(demo_02_sba_http2 PRIVATE
    3gpp_core
)
