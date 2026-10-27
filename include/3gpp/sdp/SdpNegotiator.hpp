#pragma once

#include <string>
#include <vector>
#include <string_view>
#include "3gpp/sdp/Sdp.hpp"

namespace gpp::sdp {

struct CodecPreference {
    std::string encoding_name; // e.g. "EVS", "AMR-WB", "AMR", "PCMU"
    uint32_t clock_rate{0};    // 0 means any clock rate matching encoding_name
    std::string default_fmtp;  // Optional default fmtp if needed
};

struct NegotiatorConfig {
    std::string local_address{"127.0.0.1"};
    bool is_ipv6{false};
    uint16_t local_rtp_port{40000};
    MediaDirection local_direction{MediaDirection::SENDRECV};
    std::vector<CodecPreference> preferred_codecs;
};

class SdpNegotiator {
public:
    // Generate an RFC 3264 SDP Answer corresponding to an incoming SDP Offer
    static SessionDescription create_answer(
        const SessionDescription& offer,
        const NegotiatorConfig& config);
};

} // namespace gpp::sdp
