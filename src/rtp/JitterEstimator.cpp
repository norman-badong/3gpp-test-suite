#include "3gpp/rtp/JitterEstimator.hpp"
#include <algorithm>
#include <cmath>

namespace gpp::rtp {

JitterEstimator::JitterEstimator(uint32_t clock_rate)
    : clock_rate_(clock_rate) {}

void JitterEstimator::on_packet_received(const RtpPacket& packet, uint64_t arrival_time_ms) {
    if (arrival_time_ms == 0) {
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        arrival_time_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
    }
    uint32_t arrival_clock = ms_to_clock(arrival_time_ms);

    if (first_packet_) {
        first_packet_ = false;
        base_seq_ = packet.sequence_number;
        max_seq_ = packet.sequence_number;
        cycles_ = 0;
        ssrc_ = packet.ssrc;
        last_rtp_timestamp_ = packet.timestamp;
        last_arrival_clock_ = arrival_clock;
        packets_received_ = 1;
        jitter_ = 0.0;
        return;
    }

    ++packets_received_;

    // Handle 16-bit sequence number wraparound
    uint16_t diff = packet.sequence_number - max_seq_;
    if (diff < 0x8000) {
        if (packet.sequence_number < max_seq_) {
            ++cycles_;
        }
        max_seq_ = packet.sequence_number;
    }

    // RFC 3550 Appendix A.8 Interarrival Jitter Formula
    int32_t transit_diff = static_cast<int32_t>(arrival_clock - last_arrival_clock_) -
                           static_cast<int32_t>(packet.timestamp - last_rtp_timestamp_);
    double d = std::abs(static_cast<double>(transit_diff));

    jitter_ += (d - jitter_) / 16.0;

    last_rtp_timestamp_ = packet.timestamp;
    last_arrival_clock_ = arrival_clock;
}

int32_t JitterEstimator::total_lost() const {
    if (packets_received_ == 0) return 0;
    uint32_t expected = (cycles_ << 16) | (max_seq_ - base_seq_ + 1);
    if (expected > packets_received_) {
        return static_cast<int32_t>(expected - packets_received_);
    }
    return 0;
}

uint8_t JitterEstimator::fraction_lost() const {
    uint32_t expected = (cycles_ << 16) | (max_seq_ - base_seq_ + 1);
    uint32_t expected_interval = expected - last_expected_;
    uint32_t received_interval = packets_received_ - last_received_;

    last_expected_ = expected;
    last_received_ = packets_received_;

    if (expected_interval == 0 || received_interval >= expected_interval) {
        return 0;
    }
    uint32_t lost_interval = expected_interval - received_interval;
    return static_cast<uint8_t>(std::min<uint32_t>(255, (lost_interval * 256) / expected_interval));
}

ReceptionReport JitterEstimator::make_report(uint32_t last_sr, uint32_t dlsr) const {
    ReceptionReport r;
    r.ssrc = ssrc_;
    r.fraction_lost = fraction_lost();
    r.cumulative_lost = total_lost();
    r.highest_seq_received = highest_sequence();
    r.interarrival_jitter = static_cast<uint32_t>(jitter_);
    r.last_sr_timestamp = last_sr;
    r.delay_since_last_sr = dlsr;
    return r;
}

} // namespace gpp::rtp
