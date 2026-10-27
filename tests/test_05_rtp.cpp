#include <gtest/gtest.h>
#include "3gpp/rtp/RtpPacket.hpp"
#include "3gpp/rtp/RtcpPacket.hpp"
#include "3gpp/rtp/JitterEstimator.hpp"

using namespace gpp::rtp;

// =================================================================
// 1. RTP Packet Framing Tests (RFC 3550 Section 5)
// =================================================================

TEST(RtpTest, HeaderSerializationRoundTrip) {
    RtpPacket original;
    original.version = 2;
    original.padding = false;
    original.extension = false;
    original.marker = true;
    original.payload_type = 104; // AMR-WB
    original.sequence_number = 4567;
    original.timestamp = 160000;
    original.ssrc = 0xAABBCCDD;
    original.set_payload("3GPP Voice Frame Payload Bits");

    gpp::common::ByteStreamWriter writer;
    original.encode(writer);

    EXPECT_EQ(writer.size(), 12 + original.payload.size());

    gpp::common::ByteStreamReader reader(writer.data());
    auto decoded = RtpPacket::decode(reader);

    EXPECT_EQ(decoded.version, 2);
    EXPECT_FALSE(decoded.padding);
    EXPECT_FALSE(decoded.extension);
    EXPECT_TRUE(decoded.marker);
    EXPECT_EQ(decoded.payload_type, 104);
    EXPECT_EQ(decoded.sequence_number, 4567);
    EXPECT_EQ(decoded.timestamp, 160000);
    EXPECT_EQ(decoded.ssrc, 0xAABBCCDD);
    EXPECT_EQ(decoded.payload.size(), original.payload.size());

    std::string payload_str(decoded.payload.begin(), decoded.payload.end());
    EXPECT_EQ(payload_str, "3GPP Voice Frame Payload Bits");
}

TEST(RtpTest, CsrcListHandling) {
    RtpPacket pkt;
    pkt.ssrc = 0x11111111;
    pkt.csrc_list = { 0x22222222, 0x33333333 };
    pkt.sequence_number = 1;
    pkt.timestamp = 320;
    pkt.set_payload("Audio");

    gpp::common::ByteStreamWriter writer;
    pkt.encode(writer);

    // 12 bytes fixed + 2 * 4 bytes CSRC + 5 bytes payload = 25 bytes
    EXPECT_EQ(writer.size(), 12 + 8 + 5);

    gpp::common::ByteStreamReader reader(writer.data());
    auto decoded = RtpPacket::decode(reader);

    EXPECT_EQ(decoded.csrc_count, 2);
    ASSERT_EQ(decoded.csrc_list.size(), 2);
    EXPECT_EQ(decoded.csrc_list[0], 0x22222222);
    EXPECT_EQ(decoded.csrc_list[1], 0x33333333);
}

TEST(RtpTest, AmrWbFactoryPacket) {
    auto amr = RtpPacket::make_amrwb_packet(0x12345678, 10, 3200, true);
    EXPECT_EQ(amr.version, 2);
    EXPECT_TRUE(amr.marker);
    EXPECT_EQ(amr.payload_type, 104);
    EXPECT_EQ(amr.sequence_number, 10);
    EXPECT_EQ(amr.timestamp, 3200);
    EXPECT_EQ(amr.ssrc, 0x12345678);

    // AMR-WB payload header check
    ASSERT_GE(amr.payload.size(), 2);
    EXPECT_EQ(amr.payload[0], 0x20); // CMR
    EXPECT_EQ(amr.payload[1], 0x14); // TOC
}

// =================================================================
// 2. RTCP Protocol Tests (RFC 3550 Section 6)
// =================================================================

TEST(RtcpTest, ReceptionReportBlock) {
    ReceptionReport report;
    report.ssrc = 0x11223344;
    report.fraction_lost = 5;
    report.cumulative_lost = 12;
    report.highest_seq_received = 65540;
    report.interarrival_jitter = 320;
    report.last_sr_timestamp = 0x55667788;
    report.delay_since_last_sr = 65536; // 1 second in 1/65536 sec units

    gpp::common::ByteStreamWriter writer;
    report.encode(writer);

    EXPECT_EQ(writer.size(), 24);

    gpp::common::ByteStreamReader reader(writer.data());
    auto decoded = ReceptionReport::decode(reader);

    EXPECT_EQ(decoded.ssrc, 0x11223344);
    EXPECT_EQ(decoded.fraction_lost, 5);
    EXPECT_EQ(decoded.cumulative_lost, 12);
    EXPECT_EQ(decoded.highest_seq_received, 65540);
    EXPECT_EQ(decoded.interarrival_jitter, 320);
    EXPECT_EQ(decoded.last_sr_timestamp, 0x55667788);
    EXPECT_EQ(decoded.delay_since_last_sr, 65536);
}

TEST(RtcpTest, CompoundSenderReport) {
    auto compound = CompoundRtcp::make_sender_report(
        0x12345678, 160000, 50, 1600, "alice@ims.3gpp.local");

    gpp::common::ByteStreamWriter writer;
    compound.encode(writer);

    gpp::common::ByteStreamReader reader(writer.data());
    auto decoded = CompoundRtcp::decode(reader);

    ASSERT_EQ(decoded.sender_reports.size(), 1);
    const auto& sr = decoded.sender_reports[0];
    EXPECT_EQ(sr.ssrc, 0x12345678);
    EXPECT_EQ(sr.rtp_timestamp, 160000);
    EXPECT_EQ(sr.sender_packet_count, 50);
    EXPECT_EQ(sr.sender_octet_count, 1600);

    ASSERT_EQ(decoded.sdes_chunks.size(), 1);
    EXPECT_EQ(decoded.sdes_chunks[0].ssrc, 0x12345678);
    EXPECT_EQ(decoded.sdes_chunks[0].cname, "alice@ims.3gpp.local");
}

TEST(RtcpTest, CompoundReceiverReport) {
    ReceptionReport rr_block;
    rr_block.ssrc = 0x12345678;
    rr_block.interarrival_jitter = 160;

    auto compound = CompoundRtcp::make_receiver_report(
        0x87654321, rr_block, "bob@ims.3gpp.local");

    gpp::common::ByteStreamWriter writer;
    compound.encode(writer);

    gpp::common::ByteStreamReader reader(writer.data());
    auto decoded = CompoundRtcp::decode(reader);

    ASSERT_EQ(decoded.receiver_reports.size(), 1);
    EXPECT_EQ(decoded.receiver_reports[0].ssrc, 0x87654321);
    ASSERT_EQ(decoded.receiver_reports[0].reports.size(), 1);
    EXPECT_EQ(decoded.receiver_reports[0].reports[0].interarrival_jitter, 160);

    ASSERT_EQ(decoded.sdes_chunks.size(), 1);
    EXPECT_EQ(decoded.sdes_chunks[0].cname, "bob@ims.3gpp.local");
}

// =================================================================
// 3. Jitter Estimator & RFC 3550 Algorithm
// =================================================================

TEST(JitterTest, SmoothJitterCalculation) {
    JitterEstimator estimator(16000); // 16 kHz clock (16 samples per millisecond)

    // Packet 1 sent at t=0, arrives at t=20ms
    auto p1 = RtpPacket::make_amrwb_packet(0x1111, 1, 0);
    estimator.on_packet_received(p1, 20);

    // Packet 2 sent at t=20ms (ts=320), arrives at t=40ms (exact 20ms transit time -> 0 jitter)
    auto p2 = RtpPacket::make_amrwb_packet(0x1111, 2, 320);
    estimator.on_packet_received(p2, 40);

    EXPECT_EQ(estimator.jitter_samples(), 0.0);
    EXPECT_EQ(estimator.total_received(), 2);
    EXPECT_EQ(estimator.total_lost(), 0);

    // Packet 3 sent at t=40ms (ts=640), arrives at t=70ms (delayed by 10ms -> transit diff = 10ms = 160 samples)
    auto p3 = RtpPacket::make_amrwb_packet(0x1111, 3, 640);
    estimator.on_packet_received(p3, 70);

    // Jitter = 0 + (160 - 0) / 16 = 10 samples
    EXPECT_DOUBLE_EQ(estimator.jitter_samples(), 10.0);

    // Packet 4 arrives with packet loss (seq jumps from 3 to 5)
    auto p5 = RtpPacket::make_amrwb_packet(0x1111, 5, 1280);
    estimator.on_packet_received(p5, 110);

    EXPECT_EQ(estimator.total_received(), 4);
    EXPECT_EQ(estimator.total_lost(), 1); // Sequence 4 was lost
}
