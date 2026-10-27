#include <iostream>
#include <thread>
#include <chrono>
#include "3gpp/common/Logger.hpp"
#include "3gpp/common/PcapWriter.hpp"
#include "3gpp/ip/Ipv4Header.hpp"
#include "3gpp/ip/UdpPacket.hpp"
#include "3gpp/ip/Socket.hpp"
#include "3gpp/rtp/RtpPacket.hpp"
#include "3gpp/rtp/RtcpPacket.hpp"
#include "3gpp/rtp/JitterEstimator.hpp"

using namespace gpp;

void dump_udp_payload_to_pcap(common::PcapWriter& pcap,
                              const ip::Ipv4Address& src_ip, uint16_t src_port,
                              const ip::Ipv4Address& dst_ip, uint16_t dst_port,
                              std::span<const uint8_t> payload) {
    ip::Ipv4Header ip_hdr;
    ip_hdr.src_ip = src_ip;
    ip_hdr.dst_ip = dst_ip;
    ip_hdr.protocol = 17; // UDP

    ip::UdpPacket udp;
    udp.src_port = src_port;
    udp.dst_port = dst_port;
    udp.set_payload(payload);

    common::ByteStreamWriter writer;
    ip_hdr.total_length = static_cast<uint16_t>(20 + udp.length);
    ip_hdr.encode(writer);
    udp.encode(writer, &ip_hdr.src_ip, &ip_hdr.dst_ip);

    pcap.write_ipv4(writer.data());
}

int main() {
    common::Logger::instance().set_level(common::LogLevel::DEBUG);
    GPP_LOG_INFO("MAIN", "==================================================================");
    GPP_LOG_INFO("MAIN", " 3GPP Test Suite - Lesson 5: VoLTE / VoNR RTP & RTCP Media Stream ");
    GPP_LOG_INFO("MAIN", "==================================================================");

    common::PcapWriter pcap("output_05_rtp_stream.pcap");
    GPP_LOG_INFO("MAIN", "Writing captured RTP voice & RTCP packets to 'output_05_rtp_stream.pcap'...");

    const ip::Ipv4Address ue1_ip(192, 168, 1, 10);
    const ip::Ipv4Address ue2_ip(192, 168, 1, 20);
    constexpr uint16_t RTP_PORT = 50004;
    constexpr uint16_t RTCP_PORT = 50005;

    // Sockets for live loopback communication
    ip::UdpSocket rx_rtp_sock;
    if (!rx_rtp_sock.bind("127.0.0.1", 0)) {
        GPP_LOG_ERROR("RECEIVER", "Failed to bind RTP socket");
        return 1;
    }
    uint16_t local_rx_rtp_port = rx_rtp_sock.local_port();

    ip::UdpSocket rx_rtcp_sock;
    if (!rx_rtcp_sock.bind("127.0.0.1", 0)) {
        GPP_LOG_ERROR("RECEIVER", "Failed to bind RTCP socket");
        return 1;
    }
    uint16_t local_rx_rtcp_port = rx_rtcp_sock.local_port();

    constexpr uint32_t SENDER_SSRC = 0x11223344;
    constexpr uint32_t RECEIVER_SSRC = 0x55667788;
    constexpr uint32_t CLOCK_RATE = 16000; // 16 kHz for AMR-WB
    constexpr uint32_t FRAME_DURATION_MS = 20;
    constexpr uint32_t TICKS_PER_FRAME = (CLOCK_RATE * FRAME_DURATION_MS) / 1000; // 320 ticks
    constexpr int NUM_PACKETS = 25; // 25 frames * 20 ms = 500 ms of real-time audio

    rtp::JitterEstimator jitter_estimator(CLOCK_RATE);

    // Receiver Thread (UE2)
    std::thread receiver_thread([&]() {
        std::array<uint8_t, 2048> rx_buf{};
        std::string src_h;
        uint16_t src_p = 0;

        for (int i = 0; i < NUM_PACKETS; ++i) {
            ssize_t n = rx_rtp_sock.recv_from(rx_buf, src_h, src_p, 1000);
            if (n > 0) {
                common::ByteStreamReader r(std::span<const uint8_t>(rx_buf.data(), n));
                auto pkt = rtp::RtpPacket::decode(r);
                jitter_estimator.on_packet_received(pkt);
            }
        }

        // Send RTCP Receiver Report (RR) + SDES (CNAME) back
        auto report_block = jitter_estimator.make_report();
        auto compound_rr = rtp::CompoundRtcp::make_receiver_report(
            RECEIVER_SSRC, report_block, "bob@ims.mnc001.mcc001.3gppnetwork.org");

        common::ByteStreamWriter rr_writer;
        compound_rr.encode(rr_writer);

        // Export RR to PCAP
        dump_udp_payload_to_pcap(pcap, ue2_ip, RTCP_PORT, ue1_ip, RTCP_PORT, rr_writer.data());
        GPP_LOG_INFO("RECEIVER", "Sent RTCP Receiver Report: Jitter=" +
                                 std::to_string(jitter_estimator.jitter_ms()) + " ms, Total Lost=" +
                                 std::to_string(jitter_estimator.total_lost()));
    });

    // Sender Thread (UE1)
    ip::UdpSocket tx_sock;
    uint32_t timestamp = 10000;
    uint16_t seq = 1;

    GPP_LOG_INFO("SENDER", "Streaming " + std::to_string(NUM_PACKETS) +
                           " AMR-WB (16 kHz, 20ms) VoLTE voice frames...");

    for (int i = 0; i < NUM_PACKETS; ++i) {
        bool marker = (i == 0); // Marker bit on first packet (start of talkspurt)
        auto pkt = rtp::RtpPacket::make_amrwb_packet(SENDER_SSRC, seq++, timestamp, marker);
        timestamp += TICKS_PER_FRAME;

        common::ByteStreamWriter writer;
        pkt.encode(writer);

        tx_sock.send_to(writer.data(), "127.0.0.1", local_rx_rtp_port);
        dump_udp_payload_to_pcap(pcap, ue1_ip, RTP_PORT, ue2_ip, RTP_PORT, writer.data());

        // Emit an RTCP Sender Report halfway through
        if (i == 12) {
            auto compound_sr = rtp::CompoundRtcp::make_sender_report(
                SENDER_SSRC, timestamp, i + 1, (i + 1) * 34,
                "alice@ims.mnc001.mcc001.3gppnetwork.org");

            common::ByteStreamWriter sr_writer;
            compound_sr.encode(sr_writer);
            tx_sock.send_to(sr_writer.data(), "127.0.0.1", local_rx_rtcp_port);
            dump_udp_payload_to_pcap(pcap, ue1_ip, RTCP_PORT, ue2_ip, RTCP_PORT, sr_writer.data());
            GPP_LOG_INFO("SENDER", "Sent RTCP Sender Report: Packets Sent=" + std::to_string(i + 1));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5)); // High speed test playback
    }

    receiver_thread.join();
    pcap.close();

    GPP_LOG_INFO("MAIN", "QoS Stats: Total Received=" + std::to_string(jitter_estimator.total_received()) +
                         ", Lost=" + std::to_string(jitter_estimator.total_lost()) +
                         ", Interarrival Jitter=" + std::to_string(jitter_estimator.jitter_ms()) + " ms");
    GPP_LOG_INFO("MAIN", "Lesson 5 Complete! Generated 'output_05_rtp_stream.pcap' with " +
                         std::to_string(pcap.packet_count()) + " packets.");
    return 0;
}
