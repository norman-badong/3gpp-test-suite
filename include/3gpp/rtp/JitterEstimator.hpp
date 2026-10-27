#pragma once

#include <cstdint>
#include <chrono>
#include "3gpp/rtp/RtpPacket.hpp"
#include "3gpp/rtp/RtcpPacket.hpp"

namespace gpp::rtp {

class JitterEstimator {
public:
    explicit JitterEstimator(uint32_t clock_rate = 16000); // 16 kHz default for VoLTE AMR-WB / VoNR EVS

    // Process an incoming RTP packet and update statistical jitter & packet loss
    void on_packet_received(const RtpPacket& packet, uint64_t arrival_time_ms = 0);

    [[nodiscard]] double jitter_samples() const { return jitter_; }
    [[nodiscard]] double jitter_ms() const { return (jitter_ * 1000.0) / clock_rate_; }
    [[nodiscard]] uint32_t total_received() const { return packets_received_; }
    [[nodiscard]] int32_t total_lost() const;
    [[nodiscard]] uint8_t fraction_lost() const;
    [[nodiscard]] uint32_t highest_sequence() const { return (cycles_ << 16) | max_seq_; }

    // Generates an RFC 3550 ReceptionReport block for RTCP RR
    [[nodiscard]] ReceptionReport make_report(uint32_t last_sr = 0, uint32_t dlsr = 0) const;

private:
    uint32_t clock_rate_{16000};
    bool first_packet_{true};

    uint16_t base_seq_{0};
    uint16_t max_seq_{0};
    uint32_t cycles_{0};
    uint32_t ssrc_{0};

    uint32_t last_rtp_timestamp_{0};
    uint32_t last_arrival_clock_{0};

    double jitter_{0.0};
    uint32_t packets_received_{0};

    // Tracking for fraction lost between successive RTCP reports
    mutable uint32_t last_expected_{0};
    mutable uint32_t last_received_{0};

    [[nodiscard]] uint32_t ms_to_clock(uint64_t ms) const {
        return static_cast<uint32_t>((ms * clock_rate_) / 1000);
    }
};

} // namespace gpp::rtp
