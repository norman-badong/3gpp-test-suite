#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <array>
#include <stdexcept>
#include <iomanip>

#include "3gpp/common/Logger.hpp"
#include "3gpp/common/PcapWriter.hpp"
#include "3gpp/common/ByteStream.hpp"
#include "3gpp/ip/IpAddress.hpp"
#include "3gpp/ip/Ipv4Header.hpp"
#include "3gpp/ip/UdpPacket.hpp"
#include "3gpp/ip/Socket.hpp"

#include "3gpp/lte_nas/NasCommon.hpp"
#include "3gpp/lte_nas/NasIe.hpp"
#include "3gpp/lte_nas/EmmMessage.hpp"
#include "3gpp/lte_nas/EsmMessage.hpp"

using namespace gpp;
using namespace gpp::lte_nas;

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
    GPP_LOG_INFO("MAIN", " 3GPP Test Suite - Lesson 7: LTE Attach NAS (EMM & ESM Procedures)");
    GPP_LOG_INFO("MAIN", "==================================================================");

    common::PcapWriter pcap("output_07_lte_nas.pcap");

    ip::Ipv4Address ue_ip(127, 0, 0, 1);
    ip::Ipv4Address mme_ip(127, 0, 0, 2);

    ip::UdpSocket mme_sock;
    if (!mme_sock.bind("127.0.0.1", 0)) {
        GPP_LOG_ERROR("MAIN", "Failed to bind MME UDP socket");
        return 1;
    }
    uint16_t mme_port = mme_sock.local_port();
    GPP_LOG_INFO("MME", "MME listening on port " + std::to_string(mme_port));

    // MME thread
    std::thread mme_thread([&]() {
        std::array<uint8_t, 2048> buf{};
        std::string client_host;
        uint16_t client_port = 0;

        // 1. Receive Attach Request
        ssize_t n = mme_sock.recv_from(buf, client_host, client_port, 2000);
        if (n <= 0) {
            GPP_LOG_ERROR("MME", "Timed out waiting for Attach Request");
            return;
        }

        std::span<const uint8_t> req_span(buf.data(), static_cast<size_t>(n));
        auto attach_req = AttachRequest::decode(req_span);
        GPP_LOG_INFO("MME", "Received Attach Request from IMSI=" + attach_req.mobile_id.imsi +
                            " (AttachType=0x0" + std::to_string(attach_req.eps_attach_type) + ")");

        auto pdn_req = PdnConnectivityRequest::decode(attach_req.esm_message_container);
        GPP_LOG_INFO("MME", "Embedded ESM PDN Connectivity Request: PDN Type=" +
                            std::to_string(pdn_req.pdn_type) + ", PTI=" +
                            std::to_string(pdn_req.procedure_transaction_id));

        // 2. Build and Send Attach Accept with Activate Default EPS Bearer Context Request
        ActivateDefaultEpsBearerContextRequest bearer_req;
        bearer_req.eps_bearer_id = 5;
        bearer_req.procedure_transaction_id = pdn_req.procedure_transaction_id;
        bearer_req.qos.qci = 9;
        bearer_req.apn.apn = "internet";
        bearer_req.pdn_address.pdn_type = 0x01; // IPv4
        bearer_req.pdn_address.ipv4 = {10, 45, 0, 1};
        auto esm_bearer_bytes = bearer_req.encode();

        AttachAccept attach_accept;
        attach_accept.eps_attach_result = 0x01; // EPS only
        attach_accept.t3412_value = 0x21;       // 54 min
        attach_accept.tai_list.mcc = "001";
        attach_accept.tai_list.mnc = "01";
        attach_accept.tai_list.tacs = {0x1234};
        attach_accept.esm_message_container = esm_bearer_bytes;
        attach_accept.guti.mcc = "001";
        attach_accept.guti.mnc = "01";
        attach_accept.guti.mme_group_id = 1;
        attach_accept.guti.mme_code = 1;
        attach_accept.guti.m_tmsi = 0xABCD1234;

        auto accept_bytes = attach_accept.encode();
        mme_sock.send_to(accept_bytes, client_host, client_port);
        GPP_LOG_INFO("MME", "Sent Attach Accept (GUTI M-TMSI=0xABCD1234, IP=10.45.0.1, QCI=9)");

        // 3. Receive Attach Complete
        n = mme_sock.recv_from(buf, client_host, client_port, 2000);
        if (n <= 0) {
            GPP_LOG_ERROR("MME", "Timed out waiting for Attach Complete");
            return;
        }

        std::span<const uint8_t> comp_span(buf.data(), static_cast<size_t>(n));
        auto attach_comp = AttachComplete::decode(comp_span);
        auto act_accept = ActivateDefaultEpsBearerContextAccept::decode(attach_comp.esm_message_container);
        GPP_LOG_INFO("MME", "Received Attach Complete + Activate Default Bearer Accept (EBI=" +
                            std::to_string(act_accept.eps_bearer_id) + ")");
    });

    // UE side
    ip::UdpSocket ue_sock;
    if (!ue_sock.bind("127.0.0.1", 0)) {
        GPP_LOG_ERROR("MAIN", "Failed to bind UE UDP socket");
        mme_thread.join();
        return 1;
    }
    uint16_t ue_port = ue_sock.local_port();
    GPP_LOG_INFO("UE", "UE configured on port " + std::to_string(ue_port));

    // Step 1: UE prepares PDN Connectivity Request and Attach Request
    PdnConnectivityRequest pdn_req;
    pdn_req.eps_bearer_id = 0;
    pdn_req.procedure_transaction_id = 1;
    pdn_req.pdn_type = 0x01;    // IPv4
    pdn_req.request_type = 0x01; // Initial request
    auto esm_pdu = pdn_req.encode();

    AttachRequest attach_req;
    attach_req.eps_attach_type = 0x01; // EPS Attach
    attach_req.nas_key_set_id = 0x07;  // No key available
    attach_req.mobile_id.imsi = "001010123456789";
    attach_req.ue_network_capability = {0xE0, 0x00, 0x00, 0x00};
    attach_req.esm_message_container = esm_pdu;
    auto attach_req_bytes = attach_req.encode();

    GPP_LOG_INFO("UE", "Sending Attach Request with IMSI=" + attach_req.mobile_id.imsi);
    ue_sock.send_to(attach_req_bytes, "127.0.0.1", mme_port);
    dump_nas_to_pcap(pcap, ue_ip, ue_port, mme_ip, mme_port, attach_req_bytes);

    // Step 2: UE receives Attach Accept
    std::array<uint8_t, 2048> ue_recv_buf{};
    std::string sender_host;
    uint16_t sender_port = 0;
    ssize_t n = ue_sock.recv_from(ue_recv_buf, sender_host, sender_port, 2000);
    if (n <= 0) {
        GPP_LOG_ERROR("UE", "Timed out waiting for Attach Accept");
        mme_thread.join();
        return 1;
    }

    std::vector<uint8_t> accept_pdu(ue_recv_buf.begin(), ue_recv_buf.begin() + n);
    dump_nas_to_pcap(pcap, mme_ip, mme_port, ue_ip, ue_port, accept_pdu);

    auto attach_accept = AttachAccept::decode(accept_pdu);
    GPP_LOG_INFO("UE", "Received Attach Accept! EPS Result=" +
                        std::to_string(attach_accept.eps_attach_result) +
                        ", Assigned GUTI M-TMSI=0xABCD1234");

    auto bearer_req = ActivateDefaultEpsBearerContextRequest::decode(attach_accept.esm_message_container);
    std::string assigned_ip = std::to_string(bearer_req.pdn_address.ipv4[0]) + "." +
                              std::to_string(bearer_req.pdn_address.ipv4[1]) + "." +
                              std::to_string(bearer_req.pdn_address.ipv4[2]) + "." +
                              std::to_string(bearer_req.pdn_address.ipv4[3]);
    GPP_LOG_INFO("UE", "Default EPS Bearer activated: EBI=" + std::to_string(bearer_req.eps_bearer_id) +
                        ", QCI=" + std::to_string(bearer_req.qos.qci) +
                        ", APN='" + bearer_req.apn.apn + "', IPv4=" + assigned_ip);

    // Step 3: UE sends Attach Complete
    ActivateDefaultEpsBearerContextAccept act_accept;
    act_accept.eps_bearer_id = bearer_req.eps_bearer_id;
    act_accept.procedure_transaction_id = bearer_req.procedure_transaction_id;
    auto act_accept_bytes = act_accept.encode();

    AttachComplete attach_comp;
    attach_comp.esm_message_container = act_accept_bytes;
    auto attach_comp_bytes = attach_comp.encode();

    GPP_LOG_INFO("UE", "Sending Attach Complete (Default Bearer Context Activated)");
    ue_sock.send_to(attach_comp_bytes, "127.0.0.1", mme_port);
    dump_nas_to_pcap(pcap, ue_ip, ue_port, mme_ip, mme_port, attach_comp_bytes);

    mme_thread.join();

    pcap.close();
    GPP_LOG_INFO("MAIN", "==================================================================");
    GPP_LOG_INFO("MAIN", "Lesson 7 LTE Attach NAS demo completed successfully!");
    GPP_LOG_INFO("MAIN", "Trace written to output_07_lte_nas.pcap (" +
                         std::to_string(pcap.packet_count()) + " packets)");
    GPP_LOG_INFO("MAIN", "==================================================================");

    return 0;
}
