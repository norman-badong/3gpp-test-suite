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
    sba/Http2Frame.cpp
    sba/Hpack.cpp
    sba/TlsSocket.cpp
    sba/SbaSession.cpp
    sdp/Sdp.cpp
    sdp/SdpNegotiator.cpp
    sip/SipUri.cpp
    sip/SipHeader.cpp
    sip/SipMessage.cpp
    sip/SipDialog.cpp
    rtp/RtpPacket.cpp
    rtp/RtcpPacket.cpp
    rtp/JitterEstimator.cpp
    diameter/DiameterAvp.cpp
    diameter/DiameterMessage.cpp
    diameter/DiameterFactory.cpp
    diameter/DiameterStack.cpp
    lte_nas/NasCommon.cpp
    lte_nas/NasIe.cpp
    lte_nas/EmmMessage.cpp
    lte_nas/EsmMessage.cpp
    nr_nas/NrNasCommon.cpp
    nr_nas/NrNasIe.cpp
    nr_nas/GmmMessage.cpp
    nr_nas/GsmMessage.cpp
)

target_include_directories(3gpp_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(3gpp_core PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)
