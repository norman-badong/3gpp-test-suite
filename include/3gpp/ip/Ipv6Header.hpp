#pragma once

#include <cstdint>
#include "3gpp/common/ByteStream.hpp"
#include "3gpp/ip/IpAddress.hpp"

namespace gpp::ip {

struct Ipv6Header {
    uint8_t version{6};
    uint8_t traffic_class{0};
    uint32_t flow_label{0};             // 20 bits
    uint16_t payload_length{0};         // Length of payload following 40-byte IPv6 header
    uint8_t next_header{17};            // 17 = UDP, 6 = TCP
    uint8_t hop_limit{64};
    Ipv6Address src_ip{Ipv6Address::Loopback};
    Ipv6Address dst_ip{Ipv6Address::Loopback};

    static constexpr size_t FixedHeaderSize = 40;

    void encode(common::ByteStreamWriter& writer) const;
    static Ipv6Header decode(common::ByteStreamReader& reader);
};

} // namespace gpp::ip
