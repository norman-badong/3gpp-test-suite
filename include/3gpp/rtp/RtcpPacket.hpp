#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include "3gpp/common/ByteStream.hpp"

namespace gpp::rtp {

enum class RtcpType : uint8_t {
    SR   = 200, // Sender Report
    RR   = 201, // Receiver Report
    SDES = 202, // Source Description
    BYE  = 203, // Goodbye
    APP  = 204  // Application-defined
};

// RFC 3550 Section 6.4.1 Reception Report Block
struct ReceptionReport {
    uint32_t ssrc{0};                   // SSRC of source being reported on
    uint8_t fraction_lost{0};           // Fraction lost since last SR/RR (8 bits)
    int32_t cumulative_lost{0};         // Cumulative packets lost (24 bits signed)
    uint32_t highest_seq_received{0};   // Extended highest sequence number
    uint32_t interarrival_jitter{0};    // Statistical interarrival jitter (samples)
    uint32_t last_sr_timestamp{0};      // LSR (middle 32 bits of NTP in latest SR)
    uint32_t delay_since_last_sr{0};    // DLSR (units of 1/65536 seconds)

    void encode(common::ByteStreamWriter& writer) const;
    static ReceptionReport decode(common::ByteStreamReader& reader);
};

// RFC 3550 Section 6.4.1 Sender Report (SR)
struct SenderReport {
    uint32_t ssrc{0};                   // SSRC of sender
    uint64_t ntp_timestamp{0};          // 64-bit NTP timestamp (32-bit sec + 32-bit frac)
    uint32_t rtp_timestamp{0};          // RTP clock timestamp corresponding to NTP
    uint32_t sender_packet_count{0};    // Cumulative RTP packets sent
    uint32_t sender_octet_count{0};     // Cumulative payload octets sent
    std::vector<ReceptionReport> reports;

    void encode(common::ByteStreamWriter& writer) const;
    static SenderReport decode(common::ByteStreamReader& reader, uint8_t report_count);
};

// RFC 3550 Section 6.4.2 Receiver Report (RR)
struct ReceiverReport {
    uint32_t ssrc{0};                   // SSRC of receiver
    std::vector<ReceptionReport> reports;

    void encode(common::ByteStreamWriter& writer) const;
    static ReceiverReport decode(common::ByteStreamReader& reader, uint8_t report_count);
};

// RFC 3550 Section 6.5 SDES (Source Description)
struct SdesChunk {
    uint32_t ssrc{0};
    std::string cname; // Canonical Name (Type 1), mandatory in compound RTCP

    void encode(common::ByteStreamWriter& writer) const;
    static SdesChunk decode(common::ByteStreamReader& reader);
};

// Compound RTCP Packet Container (RFC 3550 Section 6.1)
class CompoundRtcp {
public:
    CompoundRtcp() = default;

    std::vector<SenderReport> sender_reports;
    std::vector<ReceiverReport> receiver_reports;
    std::vector<SdesChunk> sdes_chunks;
    std::vector<uint32_t> bye_ssrcs;

    void encode(common::ByteStreamWriter& writer) const;
    static CompoundRtcp decode(common::ByteStreamReader& reader);

    // Factory helper to build an SR + SDES compound packet
    static CompoundRtcp make_sender_report(
        uint32_t ssrc,
        uint32_t rtp_timestamp,
        uint32_t packet_count,
        uint32_t octet_count,
        std::string_view cname);

    // Factory helper to build an RR + SDES compound packet
    static CompoundRtcp make_receiver_report(
        uint32_t receiver_ssrc,
        const ReceptionReport& report,
        std::string_view cname);
};

} // namespace gpp::rtp
