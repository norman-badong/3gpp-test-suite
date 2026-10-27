#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <string_view>
#include "3gpp/common/ByteStream.hpp"

namespace gpp::rtp {

class RtpPacket {
public:
    RtpPacket() = default;

    // Header fields (RFC 3550 Section 5.1)
    uint8_t version{2};                 // Protocol version (2 bits, always 2)
    bool padding{false};                // Padding flag (1 bit)
    bool extension{false};              // Header extension flag (1 bit)
    uint8_t csrc_count{0};              // CSRC count (4 bits)
    bool marker{false};                 // Marker bit (1 bit, e.g. start of talkspurt in 3GPP voice)
    uint8_t payload_type{104};          // Payload type (7 bits, e.g. 104 for AMR-WB, 108 for EVS)
    uint16_t sequence_number{0};        // Sequence number (16 bits)
    uint32_t timestamp{0};              // Timestamp (32 bits, sample clock)
    uint32_t ssrc{0};                   // Synchronization source identifier (32 bits)
    std::vector<uint32_t> csrc_list;    // Contributing sources (0 to 15 items)

    // Payload (voice or video frame bytes)
    std::vector<uint8_t> payload;

    static constexpr size_t FixedHeaderSize = 12;

    void set_payload(std::span<const uint8_t> data);
    void set_payload(std::string_view text);

    void encode(common::ByteStreamWriter& writer) const;
    static RtpPacket decode(common::ByteStreamReader& reader);

    // Factory helper to create synthetic 3GPP voice packets (e.g. AMR-WB 20ms frame)
    static RtpPacket make_amrwb_packet(
        uint32_t ssrc,
        uint16_t seq_num,
        uint32_t timestamp,
        bool marker = false);
};

} // namespace gpp::rtp
