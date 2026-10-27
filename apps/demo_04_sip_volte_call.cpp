#include <iostream>
#include <thread>
#include <chrono>
#include "3gpp/common/Logger.hpp"
#include "3gpp/common/PcapWriter.hpp"
#include "3gpp/ip/Ipv4Header.hpp"
#include "3gpp/ip/UdpPacket.hpp"
#include "3gpp/ip/Socket.hpp"
#include "3gpp/sdp/Sdp.hpp"
#include "3gpp/sdp/SdpNegotiator.hpp"
#include "3gpp/sip/SipMessage.hpp"
#include "3gpp/sip/SipDialog.hpp"

using namespace gpp;

void dump_sip_to_pcap(common::PcapWriter& pcap,
                      const ip::Ipv4Address& src_ip, uint16_t src_port,
                      const ip::Ipv4Address& dst_ip, uint16_t dst_port,
                      const sip::SipMessage& msg) {
    std::string text = msg.serialize();

    ip::Ipv4Header ip_hdr;
    ip_hdr.src_ip = src_ip;
    ip_hdr.dst_ip = dst_ip;
    ip_hdr.protocol = 17; // UDP

    ip::UdpPacket udp;
    udp.src_port = src_port;
    udp.dst_port = dst_port;
    udp.set_payload(text);

    common::ByteStreamWriter writer;
    ip_hdr.total_length = static_cast<uint16_t>(20 + udp.length);
    ip_hdr.encode(writer);
    udp.encode(writer, &ip_hdr.src_ip, &ip_hdr.dst_ip);

    pcap.write_ipv4(writer.data());
}

int main() {
    common::Logger::instance().set_level(common::LogLevel::DEBUG);
    GPP_LOG_INFO("MAIN", "==================================================================");
    GPP_LOG_INFO("MAIN", " 3GPP Test Suite - Lesson 4: SIP VoLTE / VoNR IMS Signaling Test ");
    GPP_LOG_INFO("MAIN", "==================================================================");

    common::PcapWriter pcap("output_04_sip_volte_call.pcap");
    GPP_LOG_INFO("MAIN", "Writing captured SIP transactions to 'output_04_sip_volte_call.pcap'...");

    const ip::Ipv4Address ue_ip(192, 168, 1, 10);
    const ip::Ipv4Address pcscf_ip(192, 168, 1, 1);

    // Setup UDP sockets on loopback for live socket communication
    ip::UdpSocket pcscf_sock;
    if (!pcscf_sock.bind("127.0.0.1", 0)) {
        GPP_LOG_ERROR("P-CSCF", "Failed to bind socket");
        return 1;
    }
    uint16_t pcscf_port = pcscf_sock.local_port();
    GPP_LOG_INFO("P-CSCF", "Mock IMS P-CSCF listening on UDP port " + std::to_string(pcscf_port));

    ip::UdpSocket ue_sock;
    if (!ue_sock.bind("127.0.0.1", 0)) {
        GPP_LOG_ERROR("UE", "Failed to bind socket");
        return 1;
    }
    uint16_t ue_port = ue_sock.local_port();
    GPP_LOG_INFO("UE", "Simulated VoLTE/VoNR UE listening on UDP port " + std::to_string(ue_port));

    // Run P-CSCF / Network side thread
    std::thread server_thread([&]() {
        std::array<uint8_t, 4096> rx_buf{};
        std::string client_host;
        uint16_t client_port = 0;

        sip::SipDialog server_dialog;

        // 1. Await REGISTER
        ssize_t n = pcscf_sock.recv_from(rx_buf, client_host, client_port, 2000);
        if (n > 0) {
            std::string raw(reinterpret_cast<char*>(rx_buf.data()), n);
            auto reg_msg = sip::SipMessage::parse(raw);
            GPP_LOG_INFO("P-CSCF", "Received SIP " + reg_msg.method() + " from " + reg_msg.from().uri.to_string());

            // Reply 200 OK
            auto ok_resp = sip::SipMessage::make_response(reg_msg, 200, "OK");
            ok_resp.add_header("Service-Route", "<sip:orig@scscf.ims.mnc001.mcc001.3gppnetwork.org:5060;lr>");
            std::string ok_str = ok_resp.serialize();
            pcscf_sock.send_to(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(ok_str.data()), ok_str.size()),
                               client_host, client_port);
            dump_sip_to_pcap(pcap, pcscf_ip, 5060, ue_ip, 5060, ok_resp);
            GPP_LOG_INFO("P-CSCF", "Sent SIP 200 OK (Registration Accepted)");
        }

        // 2. Await INVITE
        n = pcscf_sock.recv_from(rx_buf, client_host, client_port, 2000);
        if (n > 0) {
            std::string raw(reinterpret_cast<char*>(rx_buf.data()), n);
            auto inv_msg = sip::SipMessage::parse(raw);
            GPP_LOG_INFO("P-CSCF", "Received SIP " + inv_msg.method() + " for " + inv_msg.request_uri().to_string());

            server_dialog.init_as_uas(inv_msg, "pcscf-tag-999");

            // Send 180 Ringing
            auto ringing = sip::SipMessage::make_response(inv_msg, 180, "Ringing", "pcscf-tag-999");
            std::string ring_str = ringing.serialize();
            pcscf_sock.send_to(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(ring_str.data()), ring_str.size()),
                               client_host, client_port);
            dump_sip_to_pcap(pcap, pcscf_ip, 5060, ue_ip, 5060, ringing);
            GPP_LOG_INFO("P-CSCF", "Sent SIP 180 Ringing");

            // Evaluate SDP Offer and construct SDP Answer
            auto offer_opt = inv_msg.get_sdp();
            if (offer_opt) {
                sdp::NegotiatorConfig callee_config{
                    .local_address = "192.168.1.20",
                    .local_rtp_port = 50004,
                    .preferred_codecs = { { "AMR-WB", 16000, "octet-align=1" } }
                };
                auto sdp_answer = sdp::SdpNegotiator::create_answer(*offer_opt, callee_config);

                // Send 200 OK with SDP Answer
                auto ok_call = sip::SipMessage::make_response(inv_msg, 200, "OK", "pcscf-tag-999");
                ok_call.add_contact(sip::NameAddrHeader(sip::SipUri("bob", "192.168.1.20", 5060)));
                ok_call.set_sdp(sdp_answer);

                std::string ok_call_str = ok_call.serialize();
                pcscf_sock.send_to(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(ok_call_str.data()), ok_call_str.size()),
                                   client_host, client_port);
                dump_sip_to_pcap(pcap, pcscf_ip, 5060, ue_ip, 5060, ok_call);
                GPP_LOG_INFO("P-CSCF", "Sent SIP 200 OK with SDP Answer (Call Accepted)");
            }
        }

        // 3. Await ACK
        n = pcscf_sock.recv_from(rx_buf, client_host, client_port, 2000);
        if (n > 0) {
            std::string raw(reinterpret_cast<char*>(rx_buf.data()), n);
            auto ack_msg = sip::SipMessage::parse(raw);
            GPP_LOG_INFO("P-CSCF", "Received SIP " + ack_msg.method() + "! Media Session Active.");
        }

        // 4. Await BYE
        n = pcscf_sock.recv_from(rx_buf, client_host, client_port, 2000);
        if (n > 0) {
            std::string raw(reinterpret_cast<char*>(rx_buf.data()), n);
            auto bye_msg = sip::SipMessage::parse(raw);
            GPP_LOG_INFO("P-CSCF", "Received SIP " + bye_msg.method() + ". Call Terminating.");

            // Reply 200 OK
            auto ok_bye = sip::SipMessage::make_response(bye_msg, 200, "OK");
            std::string ok_bye_str = ok_bye.serialize();
            pcscf_sock.send_to(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(ok_bye_str.data()), ok_bye_str.size()),
                               client_host, client_port);
            dump_sip_to_pcap(pcap, pcscf_ip, 5060, ue_ip, 5060, ok_bye);
            GPP_LOG_INFO("P-CSCF", "Sent SIP 200 OK (Call Disconnected)");
        }
    });

    // -------------------------------------------------------------
    // Caller UE side actions
    // -------------------------------------------------------------
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    sip::SipUri ims_domain("", "ims.mnc001.mcc001.3gppnetwork.org", 5060);
    sip::NameAddrHeader alice_header(
        sip::SipUri("alice", "ims.mnc001.mcc001.3gppnetwork.org", 5060),
        "Alice",
        "ue-alice-tag-1234"
    );
    sip::NameAddrHeader bob_header(
        sip::SipUri("bob", "ims.mnc001.mcc001.3gppnetwork.org", 5060),
        "Bob"
    );
    sip::NameAddrHeader contact_header(
        sip::SipUri("alice", "192.168.1.10", 5060)
    );

    // 1. Send REGISTER
    GPP_LOG_INFO("UE", "--- Procedure 1: IMS Registration ---");
    auto reg = sip::SipMessage::make_register(
        ims_domain, alice_header, alice_header, contact_header,
        1, "reg-callid-001@192.168.1.10", 3600);

    std::string reg_str = reg.serialize();
    ue_sock.send_to(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(reg_str.data()), reg_str.size()),
                    "127.0.0.1", pcscf_port);
    dump_sip_to_pcap(pcap, ue_ip, 5060, pcscf_ip, 5060, reg);
    GPP_LOG_INFO("UE", "Sent SIP REGISTER to P-CSCF");

    std::array<uint8_t, 4096> resp_buf{};
    std::string from_host;
    uint16_t from_port = 0;
    ssize_t n = ue_sock.recv_from(resp_buf, from_host, from_port, 2000);
    if (n > 0) {
        auto resp = sip::SipMessage::parse(std::string_view(reinterpret_cast<char*>(resp_buf.data()), n));
        GPP_LOG_INFO("UE", "Received " + std::to_string(resp.status_code()) + " " + resp.reason_phrase());
    }

    // 2. Send INVITE (VoLTE / VoNR Call Setup)
    GPP_LOG_INFO("UE", "--- Procedure 2: VoLTE/VoNR Call Setup ---");
    auto sdp_offer = sdp::SessionDescription::make_vonr_evs_offer("192.168.1.10", 49170);
    auto invite = sip::SipMessage::make_invite(
        bob_header.uri, alice_header, bob_header, contact_header,
        101, "callid-volte-987654@192.168.1.10", sdp_offer);

    sip::SipDialog client_dialog;
    client_dialog.init_as_uac(invite);

    std::string inv_str = invite.serialize();
    ue_sock.send_to(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(inv_str.data()), inv_str.size()),
                    "127.0.0.1", pcscf_port);
    dump_sip_to_pcap(pcap, ue_ip, 5060, pcscf_ip, 5060, invite);
    GPP_LOG_INFO("UE", "Sent SIP INVITE with SDP Offer");

    // Receive 180 Ringing
    n = ue_sock.recv_from(resp_buf, from_host, from_port, 2000);
    if (n > 0) {
        auto resp = sip::SipMessage::parse(std::string_view(reinterpret_cast<char*>(resp_buf.data()), n));
        client_dialog.handle_response(resp);
        GPP_LOG_INFO("UE", "Received " + std::to_string(resp.status_code()) + " " + resp.reason_phrase() +
                           " (Dialog State: " + std::string(sip::to_string(client_dialog.state())) + ")");
    }

    // Receive 200 OK with SDP Answer
    n = ue_sock.recv_from(resp_buf, from_host, from_port, 2000);
    if (n > 0) {
        auto resp = sip::SipMessage::parse(std::string_view(reinterpret_cast<char*>(resp_buf.data()), n));
        client_dialog.handle_response(resp);
        GPP_LOG_INFO("UE", "Received " + std::to_string(resp.status_code()) + " " + resp.reason_phrase() +
                           " (Dialog State: " + std::string(sip::to_string(client_dialog.state())) + ")");

        auto answer_opt = resp.get_sdp();
        if (answer_opt) {
            GPP_LOG_INFO("UE", "Negotiated Remote Media Port: " + std::to_string(answer_opt->media[0].port) +
                               ", Selected Codec: " + answer_opt->media[0].rtp_maps[0].encoding_name);
        }

        // Send ACK
        auto ack = client_dialog.make_ack();
        std::string ack_str = ack.serialize();
        ue_sock.send_to(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(ack_str.data()), ack_str.size()),
                        "127.0.0.1", pcscf_port);
        dump_sip_to_pcap(pcap, ue_ip, 5060, pcscf_ip, 5060, ack);
        GPP_LOG_INFO("UE", "Sent SIP ACK! Call is Active.");
    }

    // 3. Terminate Call with BYE
    GPP_LOG_INFO("UE", "--- Procedure 3: Call Teardown ---");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto bye = client_dialog.make_bye();
    std::string bye_str = bye.serialize();
    ue_sock.send_to(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(bye_str.data()), bye_str.size()),
                    "127.0.0.1", pcscf_port);
    dump_sip_to_pcap(pcap, ue_ip, 5060, pcscf_ip, 5060, bye);
    GPP_LOG_INFO("UE", "Sent SIP BYE (Dialog State: " + std::string(sip::to_string(client_dialog.state())) + ")");

    // Receive 200 OK for BYE
    n = ue_sock.recv_from(resp_buf, from_host, from_port, 2000);
    if (n > 0) {
        auto resp = sip::SipMessage::parse(std::string_view(reinterpret_cast<char*>(resp_buf.data()), n));
        GPP_LOG_INFO("UE", "Received " + std::to_string(resp.status_code()) + " " + resp.reason_phrase() + " for BYE");
    }

    server_thread.join();
    pcap.close();
    GPP_LOG_INFO("MAIN", "Lesson 4 Complete! Generated 'output_04_sip_volte_call.pcap' with " +
                         std::to_string(pcap.packet_count()) + " packets.");
    return 0;
}
