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

#include "3gpp/rrc/Asn1Aper.hpp"
#include "3gpp/rrc/RrcTypes.hpp"
#include "3gpp/rrc/RrcMessage.hpp"

using namespace gpp;
using namespace gpp::rrc;

static void dump_rrc_to_pcap(common::PcapWriter& pcap,
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
    GPP_LOG_INFO("MAIN", " 3GPP Test Suite - Lesson 9: LTE & 5G NR RRC ASN.1 APER Signaling ");
    GPP_LOG_INFO("MAIN", "==================================================================");

    common::PcapWriter pcap("output_09_rrc.pcap");

    ip::Ipv4Address ue_ip(127, 0, 0, 1);
    ip::Ipv4Address gnb_ip(127, 0, 0, 10); // gNodeB Radio IP

    ip::UdpSocket gnb_sock;
    if (!gnb_sock.bind("127.0.0.1", 0)) {
        GPP_LOG_ERROR("MAIN", "Failed to bind gNodeB UDP socket");
        return 1;
    }
    uint16_t gnb_port = gnb_sock.local_port();
    GPP_LOG_INFO("GNB", "gNodeB RRC stack listening on port " + std::to_string(gnb_port));

    // gNodeB thread
    std::thread gnb_thread([&]() {
        std::array<uint8_t, 2048> buf{};
        std::string client_host;
        uint16_t client_port = 0;

        // 1. Receive RRCSetupRequest (UL-CCCH)
        ssize_t n = gnb_sock.recv_from(buf, client_host, client_port, 2000);
        if (n <= 0) {
            GPP_LOG_ERROR("GNB", "Timed out waiting for RRCSetupRequest");
            return;
        }

        std::span<const uint8_t> req_span(buf.data(), static_cast<size_t>(n));
        auto setup_req = RrcSetupRequest::decode(req_span);
        GPP_LOG_INFO("GNB", "Received RRCSetupRequest (UL-CCCH): Identity=0x" +
                            std::to_string(setup_req.ue_identity_val) +
                            ", Cause=" + std::to_string(static_cast<int>(setup_req.establishment_cause)) +
                            " (mo-Signalling)");

        // 2. Transmit RRCSetup (DL-CCCH)
        RrcSetup setup;
        setup.rrc_transaction_id = 0;
        setup.srb_identity = 1; // SRB1
        setup.rlc_mode = RlcMode::AM;
        setup.master_cell_group = {0x01, 0x10, 0x20, 0x30}; // MCG SpCellConfig
        auto setup_bytes = setup.encode();
        gnb_sock.send_to(setup_bytes, client_host, client_port);
        GPP_LOG_INFO("GNB", "Sent RRCSetup (DL-CCCH): SRB1 configured (RLC-AM, MasterCellGroup)");

        // 3. Receive RRCSetupComplete (UL-DCCH)
        n = gnb_sock.recv_from(buf, client_host, client_port, 2000);
        if (n <= 0) {
            GPP_LOG_ERROR("GNB", "Timed out waiting for RRCSetupComplete");
            return;
        }

        std::span<const uint8_t> comp_span(buf.data(), static_cast<size_t>(n));
        auto setup_comp = RrcSetupComplete::decode(comp_span);
        GPP_LOG_INFO("GNB", "Received RRCSetupComplete (UL-DCCH): SelectedPLMN=" +
                            std::to_string(setup_comp.selected_plmn_identity) +
                            ", Embedded NAS size=" + std::to_string(setup_comp.dedicated_nas_message.size()) + " bytes");

        // 4. Transmit RRCReconfiguration (DL-DCCH) activating DRB1
        RrcReconfiguration reconf;
        reconf.rrc_transaction_id = 1;
        reconf.drb_identity = 1; // DRB1
        reconf.qfi = 1;          // QoS Flow 1
        reconf.secondary_cell_group = {0x02, 0xAA, 0xBB};
        auto reconf_bytes = reconf.encode();
        gnb_sock.send_to(reconf_bytes, client_host, client_port);
        GPP_LOG_INFO("GNB", "Sent RRCReconfiguration (DL-DCCH): DRB1 activated (QFI=1, SCG configured)");

        // 5. Receive RRCReconfigurationComplete (UL-DCCH)
        n = gnb_sock.recv_from(buf, client_host, client_port, 2000);
        if (n <= 0) {
            GPP_LOG_ERROR("GNB", "Timed out waiting for RRCReconfigurationComplete");
            return;
        }

        std::span<const uint8_t> reconf_comp_span(buf.data(), static_cast<size_t>(n));
        auto reconf_comp = RrcReconfigurationComplete::decode(reconf_comp_span);
        GPP_LOG_INFO("GNB", "Received RRCReconfigurationComplete: TxID=" +
                            std::to_string(reconf_comp.rrc_transaction_id));
    });

    // UE side
    ip::UdpSocket ue_sock;
    if (!ue_sock.bind("127.0.0.1", 0)) {
        GPP_LOG_ERROR("MAIN", "Failed to bind UE UDP socket");
        gnb_thread.join();
        return 1;
    }
    uint16_t ue_port = ue_sock.local_port();
    GPP_LOG_INFO("UE", "UE RRC layer configured on port " + std::to_string(ue_port));

    // Step 1: UE sends RRCSetupRequest
    RrcSetupRequest setup_req;
    setup_req.ue_identity_type = InitialUeIdentityType::Ng5g_S_TMSI_Part1;
    setup_req.ue_identity_val = 0x456789ABCDULL & 0x7FFFFFFFFFULL;
    setup_req.establishment_cause = EstablishmentCause::MoSignalling;
    setup_req.spare = false;
    auto setup_req_bytes = setup_req.encode();

    GPP_LOG_INFO("UE", "Transmitting RRCSetupRequest (39-bit 5G-S-TMSI, mo-Signalling)");
    ue_sock.send_to(setup_req_bytes, "127.0.0.1", gnb_port);
    dump_rrc_to_pcap(pcap, ue_ip, ue_port, gnb_ip, gnb_port, setup_req_bytes);

    // Step 2: UE receives RRCSetup
    std::array<uint8_t, 2048> ue_recv_buf{};
    std::string sender_host;
    uint16_t sender_port = 0;
    ssize_t n = ue_sock.recv_from(ue_recv_buf, sender_host, sender_port, 2000);
    if (n <= 0) {
        GPP_LOG_ERROR("UE", "Timed out waiting for RRCSetup");
        gnb_thread.join();
        return 1;
    }

    std::vector<uint8_t> setup_pdu(ue_recv_buf.begin(), ue_recv_buf.begin() + n);
    dump_rrc_to_pcap(pcap, gnb_ip, gnb_port, ue_ip, ue_port, setup_pdu);

    auto setup = RrcSetup::decode(setup_pdu);
    GPP_LOG_INFO("UE", "Received RRCSetup: SRB" + std::to_string(setup.srb_identity) + " established (RLC-AM)");

    // Step 3: UE sends RRCSetupComplete carrying Initial NAS PDU
    RrcSetupComplete setup_comp;
    setup_comp.rrc_transaction_id = setup.rrc_transaction_id;
    setup_comp.selected_plmn_identity = 1;
    // Simulated 5GS Registration Request NAS PDU
    setup_comp.dedicated_nas_message = {0x7E, 0x00, 0x41, 0x71, 0x00, 0x0D, 0x01, 0x00, 0xF1, 0x10};
    auto setup_comp_bytes = setup_comp.encode();

    GPP_LOG_INFO("UE", "Transmitting RRCSetupComplete with embedded 5GS Registration Request");
    ue_sock.send_to(setup_comp_bytes, "127.0.0.1", gnb_port);
    dump_rrc_to_pcap(pcap, ue_ip, ue_port, gnb_ip, gnb_port, setup_comp_bytes);

    // Step 4: UE receives RRCReconfiguration
    n = ue_sock.recv_from(ue_recv_buf, sender_host, sender_port, 2000);
    if (n <= 0) {
        GPP_LOG_ERROR("UE", "Timed out waiting for RRCReconfiguration");
        gnb_thread.join();
        return 1;
    }

    std::vector<uint8_t> reconf_pdu(ue_recv_buf.begin(), ue_recv_buf.begin() + n);
    dump_rrc_to_pcap(pcap, gnb_ip, gnb_port, ue_ip, ue_port, reconf_pdu);

    auto reconf = RrcReconfiguration::decode(reconf_pdu);
    GPP_LOG_INFO("UE", "Received RRCReconfiguration: DRB" + std::to_string(reconf.drb_identity) +
                        " activated (QFI=" + std::to_string(reconf.qfi) + ")");

    // Step 5: UE transmits RRCReconfigurationComplete
    RrcReconfigurationComplete reconf_comp;
    reconf_comp.rrc_transaction_id = reconf.rrc_transaction_id;
    auto reconf_comp_bytes = reconf_comp.encode();

    GPP_LOG_INFO("UE", "Transmitting RRCReconfigurationComplete");
    ue_sock.send_to(reconf_comp_bytes, "127.0.0.1", gnb_port);
    dump_rrc_to_pcap(pcap, ue_ip, ue_port, gnb_ip, gnb_port, reconf_comp_bytes);

    gnb_thread.join();

    pcap.close();
    GPP_LOG_INFO("MAIN", "==================================================================");
    GPP_LOG_INFO("MAIN", "Lesson 9 LTE/NR RRC signaling demo completed successfully!");
    GPP_LOG_INFO("MAIN", "Trace written to output_09_rrc.pcap (" +
                         std::to_string(pcap.packet_count()) + " packets)");
    GPP_LOG_INFO("MAIN", "==================================================================");

    return 0;
}
