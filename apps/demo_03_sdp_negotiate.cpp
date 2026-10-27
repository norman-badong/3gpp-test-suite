#include <iostream>
#include <string>
#include "3gpp/common/Logger.hpp"
#include "3gpp/common/PcapWriter.hpp"
#include "3gpp/ip/Ipv4Header.hpp"
#include "3gpp/ip/UdpPacket.hpp"
#include "3gpp/sdp/Sdp.hpp"
#include "3gpp/sdp/SdpNegotiator.hpp"

using namespace gpp;

void export_sdp_to_pcap(common::PcapWriter& pcap, uint16_t src_port, uint16_t dst_port, std::string_view sdp_body, bool is_offer) {
    ip::Ipv4Header ip_hdr;
    ip_hdr.src_ip = ip::Ipv4Address(192, 168, 1, is_offer ? 10 : 20);
    ip_hdr.dst_ip = ip::Ipv4Address(192, 168, 1, is_offer ? 20 : 10);
    ip_hdr.protocol = 17; // UDP (SIP port 5060)

    // Wrap SDP in a minimal SIP container so Wireshark parses it as SIP/SDP
    std::string sip_msg;
    if (is_offer) {
        sip_msg = "INVITE sip:bob@ims.mnc001.mcc001.3gppnetwork.org SIP/2.0\r\n"
                  "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK-offer-1\r\n"
                  "From: <sip:alice@ims.mnc001.mcc001.3gppnetwork.org>;tag=tag-alice-1\r\n"
                  "To: <sip:bob@ims.mnc001.mcc001.3gppnetwork.org>\r\n"
                  "Call-ID: call-sdp-test-01@192.168.1.10\r\n"
                  "CSeq: 1 INVITE\r\n"
                  "Content-Type: application/sdp\r\n"
                  "Content-Length: " + std::to_string(sdp_body.size()) + "\r\n\r\n" +
                  std::string(sdp_body);
    } else {
        sip_msg = "SIP/2.0 200 OK\r\n"
                  "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK-offer-1;received=192.168.1.10\r\n"
                  "From: <sip:alice@ims.mnc001.mcc001.3gppnetwork.org>;tag=tag-alice-1\r\n"
                  "To: <sip:bob@ims.mnc001.mcc001.3gppnetwork.org>;tag=tag-bob-1\r\n"
                  "Call-ID: call-sdp-test-01@192.168.1.10\r\n"
                  "CSeq: 1 INVITE\r\n"
                  "Content-Type: application/sdp\r\n"
                  "Content-Length: " + std::to_string(sdp_body.size()) + "\r\n\r\n" +
                  std::string(sdp_body);
    }

    ip::UdpPacket udp;
    udp.src_port = src_port;
    udp.dst_port = dst_port;
    udp.set_payload(sip_msg);

    common::ByteStreamWriter writer;
    ip_hdr.total_length = static_cast<uint16_t>(20 + udp.length);
    ip_hdr.encode(writer);
    udp.encode(writer, &ip_hdr.src_ip, &ip_hdr.dst_ip);

    pcap.write_ipv4(writer.data());
}

int main() {
    common::Logger::instance().set_level(common::LogLevel::DEBUG);
    GPP_LOG_INFO("MAIN", "==================================================================");
    GPP_LOG_INFO("MAIN", " 3GPP Test Suite - Lesson 3: SDP VoLTE / VoNR Offer/Answer Test ");
    GPP_LOG_INFO("MAIN", "==================================================================");

    common::PcapWriter pcap("output_03_sdp_negotiate.pcap");
    GPP_LOG_INFO("MAIN", "Writing SDP Offer/Answer transactions to 'output_03_sdp_negotiate.pcap'...");

    // -------------------------------------------------------------
    // Scenario 1: 5G VoNR UE (Offering EVS & AMR-WB) calling 4G VoLTE UE (Supporting AMR-WB)
    // -------------------------------------------------------------
    GPP_LOG_INFO("SDP_DEMO", "--- Scenario 1: 5G UE (Caller) offers EVS + AMR-WB -> 4G UE accepts AMR-WB ---");

    auto offer = sdp::SessionDescription::make_vonr_evs_offer("192.168.1.10", 49170);
    std::string offer_text = offer.serialize();
    GPP_LOG_INFO("CALLER", "Generated VoNR SDP Offer:\n" + offer_text);

    // Export offer to PCAP
    export_sdp_to_pcap(pcap, 5060, 5060, offer_text, true);

    // Callee 4G VoLTE capability: Only supports AMR-WB and AMR (no EVS)
    sdp::NegotiatorConfig callee_config{
        .local_address = "192.168.1.20",
        .is_ipv6 = false,
        .local_rtp_port = 50004,
        .local_direction = sdp::MediaDirection::SENDRECV,
        .preferred_codecs = {
            { "AMR-WB", 16000, "octet-align=1" },
            { "AMR", 8000, "octet-align=1" }
        }
    };

    auto answer = sdp::SdpNegotiator::create_answer(offer, callee_config);
    std::string answer_text = answer.serialize();
    GPP_LOG_INFO("CALLEE", "Negotiated SDP Answer:\n" + answer_text);

    // Export answer to PCAP
    export_sdp_to_pcap(pcap, 5060, 5060, answer_text, false);

    // -------------------------------------------------------------
    // Scenario 2: Codec Incompatibility Test (Rejection)
    // -------------------------------------------------------------
    GPP_LOG_INFO("SDP_DEMO", "--- Scenario 2: Incompatible Codecs (Port=0 Rejection) ---");

    sdp::NegotiatorConfig callee_incompatible{
        .local_address = "192.168.1.30",
        .is_ipv6 = false,
        .local_rtp_port = 50006,
        .local_direction = sdp::MediaDirection::SENDRECV,
        .preferred_codecs = {
            { "PCMU", 8000, "" }, // G.711 only
            { "PCMA", 8000, "" }
        }
    };

    auto rejected_answer = sdp::SdpNegotiator::create_answer(offer, callee_incompatible);
    std::string rej_text = rejected_answer.serialize();
    GPP_LOG_WARN("CALLEE", "Incompatible codecs answer (Media rejected):\n" + rej_text);

    // Verify rejection port is 0
    if (!rejected_answer.media.empty() && rejected_answer.media[0].port == 0) {
        GPP_LOG_INFO("SDP_DEMO", "SUCCESS: Media stream correctly rejected with port=0 as per RFC 3264!");
    }

    pcap.close();
    GPP_LOG_INFO("MAIN", "Lesson 3 Complete! Generated 'output_03_sdp_negotiate.pcap' with " +
                         std::to_string(pcap.packet_count()) + " packets.");
    return 0;
}
