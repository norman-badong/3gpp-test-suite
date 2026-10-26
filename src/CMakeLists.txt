add_library(3gpp_core STATIC
    common/Logger.cpp
    common/ByteStream.cpp
    common/BitBuffer.cpp
    common/PcapWriter.cpp
    ip/IpAddress.cpp
    ip/Checksum.cpp
    ip/Ipv4Header.cpp
    ip/Ipv6Header.cpp
    ip/UdpPacket.cpp
    ip/TcpPacket.cpp
    ip/Socket.cpp
)

target_include_directories(3gpp_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(3gpp_core PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)
