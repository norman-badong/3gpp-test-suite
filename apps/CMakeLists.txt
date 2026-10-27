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

add_executable(demo_03_sdp_negotiate
    demo_03_sdp_negotiate.cpp
)
target_link_libraries(demo_03_sdp_negotiate PRIVATE
    3gpp_core
)

add_executable(demo_04_sip_volte_call
    demo_04_sip_volte_call.cpp
)
target_link_libraries(demo_04_sip_volte_call PRIVATE
    3gpp_core
)
