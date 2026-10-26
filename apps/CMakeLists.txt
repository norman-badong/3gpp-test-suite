add_executable(demo_01_ip_echo
    demo_01_ip_echo.cpp
)

target_link_libraries(demo_01_ip_echo PRIVATE
    3gpp_core
)
