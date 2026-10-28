#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <array>
#include <stdexcept>

#include "3gpp/common/Logger.hpp"
#include "3gpp/common/PcapWriter.hpp"
#include "3gpp/common/ByteStream.hpp"
#include "3gpp/ip/IpAddress.hpp"
#include "3gpp/ip/Ipv4Header.hpp"
#include "3gpp/ip/UdpPacket.hpp"
#include "3gpp/ip/Socket.hpp"

#include "3gpp/nr_nas/NrNasCommon.hpp"
#include "3gpp/nr_nas/NrNasIe.hpp"
#include "3gpp/nr_nas/GmmMessage.hpp"
#include "3gpp/nr_nas/GsmMessage.hpp"

using namespace gpp;
using namespace gpp::nr_nas;

static void dump_nas_to_pcap(common::PcapWriter& pcap,
                             const ip::Ipv4Address& src_ip, uint16_t src_port,
                             const ip::Ipv4Address& dst_ip, uint16_t dst_port,
                             const std::vector<uint8_t>& payload) {
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
    GPP_LOG_INFO("MAIN", " 3GPP Test Suite - Lesson 8: 5G NR Registration (5GMM & 5GSM)    ");
    GPP_LOG_INFO("MAIN", "==================================================================");

    common::PcapWriter pcap("output_08_5g_registration.pcap");

    ip::Ipv4Address ue_ip(127, 0, 0, 1);
    ip::Ipv4Address amf_ip(127, 0, 0, 3); // 5G Core AMF

    ip::UdpSocket amf_sock;
    if (!amf_sock.bind("127.0.0.1", 0)) {
        GPP_LOG_ERROR("MAIN", "Failed to bind AMF UDP socket");
        return 1;
    }
    uint16_t amf_port = amf_sock.local_port();
    GPP_LOG_INFO("AMF", "AMF listening on port " + std::to_string(amf_port));

    // AMF thread
    std::thread amf_thread([&]() {
        std::array<uint8_t, 2048> buf{};
        std::string client_host;
        uint16_t client_port = 0;

        // 1. Receive Registration Request
        ssize_t n = amf_sock.recv_from(buf, client_host, client_port, 2000);
        if (n <= 0) {
            GPP_LOG_ERROR("AMF", "Timed out waiting for Registration Request");
            return;
        }

        std::span<const uint8_t> req_span(buf.data(), static_cast<size_t>(n));
        auto reg_req = RegistrationRequest::decode(req_span);
        GPP_LOG_INFO("AMF", "Received 5GMM Registration Request:");
        GPP_LOG_INFO("AMF", "  SUCI PLMN=" + reg_req.suci.mcc + "-" + reg_req.suci.mnc +
                            ", MSIN=" + reg_req.suci.msin +
                            ", ProtectionScheme=" + std::to_string(reg_req.suci.protection_scheme));

        auto pdu_req = PduSessionEstablishmentRequest::decode(reg_req.gsm_message_container);
        GPP_LOG_INFO("AMF", "  Embedded 5GSM PDU Session Establishment Request:");
        GPP_LOG_INFO("AMF", "    PSI=" + std::to_string(pdu_req.pdu_session_id) +
                            ", PTI=" + std::to_string(pdu_req.procedure_transaction_id) +
                            ", DNN='" + pdu_req.dnn.dnn + "'" +
                            ", S-NSSAI: SST=" + std::to_string(pdu_req.s_nssai.sst) +
                            " (eMBB)");

        // 2. Build Registration Accept + PDU Session Establishment Accept
        PduSessionEstablishmentAccept pdu_acc;
        pdu_acc.pdu_session_id = pdu_req.pdu_session_id;
        pdu_acc.procedure_transaction_id = pdu_req.procedure_transaction_id;
        pdu_acc.session_type = PduSessionType::Ipv4;
        pdu_acc.ssc_mode = SscMode::Mode1;
        pdu_acc.qos_rule.qfi = 1;
        pdu_acc.qos_rule.five_qi = 9; // Best effort default
        pdu_acc.pdu_address.pdu_type = 0x01;
        pdu_acc.pdu_address.ipv4 = {10, 45, 0, 2};
        pdu_acc.s_nssai = pdu_req.s_nssai;
        pdu_acc.dnn = pdu_req.dnn;
        auto gsm_accept_bytes = pdu_acc.encode();

        RegistrationAccept reg_acc;
        reg_acc.registration_result = 0x01; // 3GPP access
        reg_acc.guti.mcc = "001";
        reg_acc.guti.mnc = "01";
        reg_acc.guti.amf_region_id = 1;
        reg_acc.guti.amf_set_id = 1;
        reg_acc.guti.amf_pointer = 1;
        reg_acc.guti.tmsi = 0x5678ABCD;
        reg_acc.t3512_value = 0x21; // 54 min
        reg_acc.allowed_nssai.push_back(pdu_req.s_nssai);
        reg_acc.gsm_message_container = gsm_accept_bytes;

        auto accept_bytes = reg_acc.encode();
        amf_sock.send_to(accept_bytes, client_host, client_port);
        GPP_LOG_INFO("AMF", "Sent Registration Accept (5G-GUTI TMSI=0x5678ABCD, IP=10.45.0.2, QFI=1, 5QI=9)");

        // 3. Receive Registration Complete
        n = amf_sock.recv_from(buf, client_host, client_port, 2000);
        if (n <= 0) {
            GPP_LOG_ERROR("AMF", "Timed out waiting for Registration Complete");
            return;
        }

        std::span<const uint8_t> comp_span(buf.data(), static_cast<size_t>(n));
        auto reg_comp = RegistrationComplete::decode(comp_span);
        GPP_LOG_INFO("AMF", "Received 5GMM Registration Complete");
    });

    // UE side
    ip::UdpSocket ue_sock;
    if (!ue_sock.bind("127.0.0.1", 0)) {
        GPP_LOG_ERROR("MAIN", "Failed to bind UE UDP socket");
        amf_thread.join();
        return 1;
    }
    uint16_t ue_port = ue_sock.local_port();
    GPP_LOG_INFO("UE", "UE configured on port " + std::to_string(ue_port));

    // Step 1: UE builds 5GSM PDU Session Establishment Request
    PduSessionEstablishmentRequest pdu_req;
    pdu_req.pdu_session_id = 1;
    pdu_req.procedure_transaction_id = 1;
    pdu_req.session_type = PduSessionType::Ipv4;
    pdu_req.ssc_mode = SscMode::Mode1;
    pdu_req.s_nssai.sst = 1; // eMBB
    pdu_req.s_nssai.sd = 0x000001;
    pdu_req.dnn.dnn = "internet";
    auto gsm_bytes = pdu_req.encode();

    // Step 2: UE builds 5GMM Registration Request with SUCI & embedded 5GSM
    RegistrationRequest reg_req;
    reg_req.registration_type = 0x01; // Initial registration
    reg_req.ng_ksi = 0x07;            // No key available
    reg_req.suci.mcc = "001";
    reg_req.suci.mnc = "01";
    reg_req.suci.routing_indicator = 0;
    reg_req.suci.protection_scheme = 0; // Null-scheme
    reg_req.suci.home_network_pki = 0;
    reg_req.suci.msin = "0123456789";
    reg_req.ue_security_capability = {0x80, 0x20}; // 5G-EA0, 5G-IA1
    reg_req.requested_nssai.push_back(pdu_req.s_nssai);
    reg_req.gsm_message_container = gsm_bytes;
    auto reg_req_bytes = reg_req.encode();

    GPP_LOG_INFO("UE", "Sending 5GMM Registration Request (SUCI MSIN=" + reg_req.suci.msin +
                       ", S-NSSAI SST=1)");
    ue_sock.send_to(reg_req_bytes, "127.0.0.1", amf_port);
    dump_nas_to_pcap(pcap, ue_ip, ue_port, amf_ip, amf_port, reg_req_bytes);

    // Step 3: UE receives Registration Accept
    std::array<uint8_t, 2048> ue_recv_buf{};
    std::string sender_host;
    uint16_t sender_port = 0;
    ssize_t n = ue_sock.recv_from(ue_recv_buf, sender_host, sender_port, 2000);
    if (n <= 0) {
        GPP_LOG_ERROR("UE", "Timed out waiting for Registration Accept");
        amf_thread.join();
        return 1;
    }

    std::vector<uint8_t> accept_pdu(ue_recv_buf.begin(), ue_recv_buf.begin() + n);
    dump_nas_to_pcap(pcap, amf_ip, amf_port, ue_ip, ue_port, accept_pdu);

    auto reg_accept = RegistrationAccept::decode(accept_pdu);
    GPP_LOG_INFO("UE", "Received Registration Accept: Result=" +
                        std::to_string(reg_accept.registration_result) +
                        ", 5G-GUTI TMSI=0x5678ABCD");

    auto pdu_accept = PduSessionEstablishmentAccept::decode(reg_accept.gsm_message_container);
    std::string assigned_ip = std::to_string(pdu_accept.pdu_address.ipv4[0]) + "." +
                              std::to_string(pdu_accept.pdu_address.ipv4[1]) + "." +
                              std::to_string(pdu_accept.pdu_address.ipv4[2]) + "." +
                              std::to_string(pdu_accept.pdu_address.ipv4[3]);
    GPP_LOG_INFO("UE", "5G PDU Session Established: PSI=" + std::to_string(pdu_accept.pdu_session_id) +
                        ", QFI=" + std::to_string(pdu_accept.qos_rule.qfi) +
                        ", 5QI=" + std::to_string(pdu_accept.qos_rule.five_qi) +
                        ", DNN='" + pdu_accept.dnn.dnn + "', IPv4=" + assigned_ip);

    // Step 4: UE sends Registration Complete
    RegistrationComplete reg_comp;
    auto reg_comp_bytes = reg_comp.encode();

    GPP_LOG_INFO("UE", "Sending 5GMM Registration Complete");
    ue_sock.send_to(reg_comp_bytes, "127.0.0.1", amf_port);
    dump_nas_to_pcap(pcap, ue_ip, ue_port, amf_ip, amf_port, reg_comp_bytes);

    amf_thread.join();

    pcap.close();
    GPP_LOG_INFO("MAIN", "==================================================================");
    GPP_LOG_INFO("MAIN", "Lesson 8 5G NR Registration demo completed successfully!");
    GPP_LOG_INFO("MAIN", "Trace written to output_08_5g_registration.pcap (" +
                         std::to_string(pcap.packet_count()) + " packets)");
    GPP_LOG_INFO("MAIN", "==================================================================");

    return 0;
}
