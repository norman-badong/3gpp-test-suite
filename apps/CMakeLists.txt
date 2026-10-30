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

add_executable(demo_05_rtp_stream
    demo_05_rtp_stream.cpp
)
target_link_libraries(demo_05_rtp_stream PRIVATE
    3gpp_core
)

add_executable(demo_06_diameter_s6a
    demo_06_diameter_s6a.cpp
)
target_link_libraries(demo_06_diameter_s6a PRIVATE
    3gpp_core
)

add_executable(demo_07_lte_nas
    demo_07_lte_nas.cpp
)
target_link_libraries(demo_07_lte_nas PRIVATE
    3gpp_core
)

add_executable(demo_08_5g_registration
    demo_08_5g_registration.cpp
)
target_link_libraries(demo_08_5g_registration PRIVATE
    3gpp_core
)

add_executable(demo_09_rrc_signaling
    demo_09_rrc_signaling.cpp
)
target_link_libraries(demo_09_rrc_signaling PRIVATE
    3gpp_core
)

add_executable(demo_10_stun_ice
    demo_10_stun_ice.cpp
)
target_link_libraries(demo_10_stun_ice PRIVATE
    3gpp_core
)
