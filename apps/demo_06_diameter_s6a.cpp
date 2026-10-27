#include <iostream>
#include <thread>
#include <chrono>
#include "3gpp/common/Logger.hpp"
#include "3gpp/common/PcapWriter.hpp"
#include "3gpp/ip/Ipv4Header.hpp"
#include "3gpp/ip/TcpPacket.hpp"
#include "3gpp/ip/Socket.hpp"
#include "3gpp/diameter/DiameterAvp.hpp"
#include "3gpp/diameter/DiameterMessage.hpp"
#include "3gpp/diameter/DiameterFactory.hpp"
#include "3gpp/diameter/DiameterStack.hpp"

using namespace gpp;
using namespace gpp::diameter;

void dump_diameter_to_pcap(common::PcapWriter& pcap,
                           const ip::Ipv4Address& src_ip, uint16_t src_port,
                           const ip::Ipv4Address& dst_ip, uint16_t dst_port,
                           uint32_t& seq_num, uint32_t ack_num,
                           const DiameterMessage& msg) {
    auto payload = msg.serialize();

    ip::Ipv4Header ip_hdr;
    ip_hdr.src_ip = src_ip;
    ip_hdr.dst_ip = dst_ip;
    ip_hdr.protocol = 6; // TCP

    ip::TcpPacket tcp;
    tcp.src_port = src_port;
    tcp.dst_port = dst_port;
    tcp.seq_number = seq_num;
    tcp.ack_number = ack_num;
    tcp.flags.psh = true;
    tcp.flags.ack = true;
    tcp.set_payload(std::span<const uint8_t>(payload.data(), payload.size()));

    common::ByteStreamWriter writer;
    ip_hdr.total_length = static_cast<uint16_t>(20 + 20 + payload.size());
    ip_hdr.encode(writer);
    tcp.encode(writer, &ip_hdr.src_ip, &ip_hdr.dst_ip);

    pcap.write_ipv4(writer.data());
    seq_num += static_cast<uint32_t>(payload.size());
}

int main() {
    common::Logger::instance().set_level(common::LogLevel::DEBUG);
    GPP_LOG_INFO("MAIN", "==================================================================");
    GPP_LOG_INFO("MAIN", " 3GPP Test Suite - Lesson 6: LTE EPC & IMS Diameter S6a Interface ");
    GPP_LOG_INFO("MAIN", "==================================================================");

    common::PcapWriter pcap("output_06_diameter_s6a.pcap");
    GPP_LOG_INFO("MAIN", "Writing captured Diameter messages to 'output_06_diameter_s6a.pcap'...");

    // Simulated Network Elements:
    // MME (Mobility Management Entity): 10.0.1.1:45678
    // HSS (Home Subscriber Server):     10.0.2.1:3868
    const ip::Ipv4Address mme_ip(10, 0, 1, 1);
    const ip::Ipv4Address hss_ip(10, 0, 2, 1);
    const uint16_t mme_port = 45678;
    const uint16_t hss_port = DIAMETER_DEFAULT_PORT; // 3868

    uint32_t mme_seq = 1000;
    uint32_t hss_seq = 2000;

    // Start Live TCP Server for HSS
    ip::TcpListener hss_listener;
    if (!hss_listener.listen("127.0.0.1", 0)) {
        GPP_LOG_ERROR("HSS", "Failed to bind TCP listener for HSS");
        return 1;
    }
    uint16_t live_hss_port = hss_listener.local_port();
    GPP_LOG_INFO("HSS", "Diameter HSS Server listening on TCP port " + std::to_string(live_hss_port));

    std::thread hss_server([&]() {
        ip::TcpSocket client_sock;
        std::string client_host;
        uint16_t client_port;

        if (!hss_listener.accept(client_sock, client_host, client_port, 3000)) {
            GPP_LOG_ERROR("HSS", "Failed to accept connection from MME");
            return;
        }
        GPP_LOG_INFO("HSS", "Accepted Diameter connection from MME (" + client_host + ":" + std::to_string(client_port) + ")");
        DiameterConnection conn(std::make_unique<ip::TcpSocket>(std::move(client_sock)));

        // 1. Receive CER (Capabilities-Exchange-Request)
        auto cer_opt = conn.receive_message(std::chrono::milliseconds(2000));
        if (!cer_opt.has_value() || cer_opt->command_code != CMD_CAPABILITIES_EXCHANGE) {
            GPP_LOG_ERROR("HSS", "Expected CER from MME");
            return;
        }
        const auto* mme_host_avp = cer_opt->find_avp(AVP_ORIGIN_HOST);
        GPP_LOG_INFO("HSS", "Received CER from: " + (mme_host_avp ? mme_host_avp->to_string() : "unknown"));

        // Respond with CEA (Capabilities-Exchange-Answer)
        auto cea = DiameterFactory::create_cea(
            *cer_opt,
            DIAMETER_SUCCESS,
            "hss01.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            hss_ip,
            VENDOR_3GPP,
            "Core-HSS-v1.0",
            {APP_3GPP_S6A}
        );
        conn.send_message(cea);
        dump_diameter_to_pcap(pcap, hss_ip, hss_port, mme_ip, mme_port, hss_seq, mme_seq, cea);
        GPP_LOG_INFO("HSS", "Sent CEA with DIAMETER_SUCCESS (2001)");

        // 2. Receive S6a AIR (Authentication-Information-Request)
        auto air_opt = conn.receive_message(std::chrono::milliseconds(2000));
        if (!air_opt.has_value() || air_opt->command_code != CMD_AUTHENTICATION_INFO) {
            GPP_LOG_ERROR("HSS", "Expected S6a AIR from MME");
            return;
        }
        const auto* imsi_avp = air_opt->find_avp(AVP_USER_NAME);
        std::string imsi = imsi_avp ? imsi_avp->to_string() : "unknown";
        GPP_LOG_INFO("HSS", "Received S6a AIR for Subscriber IMSI: " + imsi);

        // Generate E-UTRAN EPS Authentication Vector (TS 33.401 MILENAGE)
        EutranVector eps_vector;
        eps_vector.rand = {0x46, 0x5b, 0xe2, 0xa0, 0x8d, 0x34, 0x1a, 0xe9,
                           0x77, 0x18, 0x02, 0x13, 0xef, 0x45, 0x66, 0x21};
        eps_vector.xres = {0x3a, 0x7c, 0x99, 0xb2, 0xf4, 0x10, 0x2e, 0x88};
        eps_vector.autn = {0x91, 0x00, 0x23, 0x45, 0x67, 0x89, 0x00, 0x01,
                           0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
        eps_vector.kasme = {
            0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
            0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
        };

        auto aia = DiameterFactory::create_s6a_aia(
            *air_opt,
            DIAMETER_SUCCESS,
            "hss01.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            {eps_vector}
        );
        conn.send_message(aia);
        dump_diameter_to_pcap(pcap, hss_ip, hss_port, mme_ip, mme_port, hss_seq, mme_seq, aia);
        GPP_LOG_INFO("HSS", "Sent S6a AIA with E-UTRAN Auth Vector (RAND, XRES, AUTN, KASME)");

        // 3. Receive DWR (Device-Watchdog-Request)
        auto dwr_opt = conn.receive_message(std::chrono::milliseconds(2000));
        if (dwr_opt.has_value() && dwr_opt->command_code == CMD_DEVICE_WATCHDOG) {
            GPP_LOG_INFO("HSS", "Received DWR heartbeat");
            auto dwa = DiameterFactory::create_dwa(
                *dwr_opt,
                DIAMETER_SUCCESS,
                "hss01.epc.mnc001.mcc001.3gppnetwork.org",
                "epc.mnc001.mcc001.3gppnetwork.org"
            );
            conn.send_message(dwa);
            dump_diameter_to_pcap(pcap, hss_ip, hss_port, mme_ip, mme_port, hss_seq, mme_seq, dwa);
            GPP_LOG_INFO("HSS", "Sent DWA heartbeat response (Result-Code 2001)");
        }
    });

    // MME Client Execution
    auto mme_sock = std::make_unique<ip::TcpSocket>();
    if (!mme_sock->connect("127.0.0.1", live_hss_port, 2000)) {
        GPP_LOG_ERROR("MME", "Failed to connect to HSS");
        hss_server.join();
        return 1;
    }
    DiameterConnection mme_conn(std::move(mme_sock));

    // Step 1: Capabilities-Exchange-Request (CER)
    GPP_LOG_INFO("MME", "Sending CER (Application-Id = 3GPP S6a 16777251)...");
    auto cer = DiameterFactory::create_cer(
        "mme01.epc.mnc001.mcc001.3gppnetwork.org",
        "epc.mnc001.mcc001.3gppnetwork.org",
        mme_ip,
        VENDOR_3GPP,
        "Core-MME-v1.0",
        {APP_3GPP_S6A},
        1001,
        2001
    );
    dump_diameter_to_pcap(pcap, mme_ip, mme_port, hss_ip, hss_port, mme_seq, hss_seq, cer);
    mme_conn.send_message(cer);

    auto cea_opt = mme_conn.receive_message(std::chrono::milliseconds(2000));
    if (!cea_opt.has_value()) {
        GPP_LOG_ERROR("MME", "Timeout waiting for CEA");
        hss_server.join();
        return 1;
    }
    const auto* cea_res = cea_opt->find_avp(AVP_RESULT_CODE);
    uint32_t rc = cea_res ? cea_res->to_unsigned32() : 0;
    GPP_LOG_INFO("MME", "Received CEA from HSS (Result-Code: " + std::to_string(rc) + ")");

    // Step 2: S6a Authentication-Information-Request (AIR) for LTE Attach
    std::string test_imsi = "001010123456789";
    std::vector<uint8_t> visited_plmn = {0x00, 0xF1, 0x10}; // PLMN 001-01
    std::string session_id = "mme01.epc.mnc001.mcc001.3gppnetwork.org;1700000000;101";

    GPP_LOG_INFO("MME", "UE initiating LTE Attach. Requesting auth vectors for IMSI " + test_imsi);
    auto air = DiameterFactory::create_s6a_air(
        session_id,
        "mme01.epc.mnc001.mcc001.3gppnetwork.org",
        "epc.mnc001.mcc001.3gppnetwork.org",
        "epc.mnc001.mcc001.3gppnetwork.org",
        test_imsi,
        visited_plmn,
        1,
        1002,
        2002
    );
    dump_diameter_to_pcap(pcap, mme_ip, mme_port, hss_ip, hss_port, mme_seq, hss_seq, air);
    mme_conn.send_message(air);

    auto aia_opt = mme_conn.receive_message(std::chrono::milliseconds(2000));
    if (!aia_opt.has_value()) {
        GPP_LOG_ERROR("MME", "Timeout waiting for S6a AIA");
        hss_server.join();
        return 1;
    }
    const auto* aia_res = aia_opt->find_avp(AVP_RESULT_CODE);
    GPP_LOG_INFO("MME", "Received S6a AIA (Result-Code: " + std::to_string(aia_res ? aia_res->to_unsigned32() : 0) + ")");

    const auto* auth_info = aia_opt->find_avp(AVP_AUTHENTICATION_INFO, VENDOR_3GPP);
    if (auth_info) {
        auto vectors = auth_info->to_grouped();
        GPP_LOG_INFO("MME", "Successfully parsed " + std::to_string(vectors.size()) + " E-UTRAN Authentication Vector(s)");
        for (const auto& vec_avp : vectors) {
            auto fields = vec_avp.to_grouped();
            for (const auto& f : fields) {
                if (f.code == AVP_RAND) {
                    GPP_HEXDUMP("MME", "E-UTRAN RAND (16 octets)", f.to_octet_string());
                } else if (f.code == AVP_AUTN) {
                    GPP_HEXDUMP("MME", "E-UTRAN AUTN (16 octets)", f.to_octet_string());
                } else if (f.code == AVP_KASME) {
                    GPP_HEXDUMP("MME", "E-UTRAN KASME (32 octets)", f.to_octet_string());
                }
            }
        }
    }

    // Step 3: Device-Watchdog-Request (DWR)
    GPP_LOG_INFO("MME", "Sending DWR Heartbeat keepalive...");
    auto dwr = DiameterFactory::create_dwr(
        "mme01.epc.mnc001.mcc001.3gppnetwork.org",
        "epc.mnc001.mcc001.3gppnetwork.org",
        1003,
        2003
    );
    dump_diameter_to_pcap(pcap, mme_ip, mme_port, hss_ip, hss_port, mme_seq, hss_seq, dwr);
    mme_conn.send_message(dwr);

    auto dwa_opt = mme_conn.receive_message(std::chrono::milliseconds(2000));
    if (dwa_opt.has_value()) {
        const auto* dwa_res = dwa_opt->find_avp(AVP_RESULT_CODE);
        GPP_LOG_INFO("MME", "Received DWA Heartbeat response (Result-Code: " +
                     std::to_string(dwa_res ? dwa_res->to_unsigned32() : 0) + ")");
    }

    hss_server.join();

    GPP_LOG_INFO("MAIN", "Lesson 6 Complete! Generated 'output_06_diameter_s6a.pcap' with 6 Diameter packets.");
    return 0;
}
