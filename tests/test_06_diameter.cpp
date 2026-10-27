#include <gtest/gtest.h>
#include "3gpp/diameter/DiameterAvp.hpp"
#include "3gpp/diameter/DiameterMessage.hpp"
#include "3gpp/diameter/DiameterFactory.hpp"
#include "3gpp/diameter/DiameterStack.hpp"

#include <thread>

using namespace gpp;
using namespace gpp::diameter;

TEST(DiameterAvpTest, Unsigned32EncodingDecoding) {
    auto avp = DiameterAvp::create_unsigned32(AVP_RESULT_CODE, DIAMETER_SUCCESS);
    EXPECT_EQ(avp.code, AVP_RESULT_CODE);
    EXPECT_TRUE(avp.is_mandatory());
    EXPECT_FALSE(avp.is_vendor_specific());
    EXPECT_EQ(avp.to_unsigned32(), 2001u);

    auto serialized = avp.serialize();
    // Header (8 bytes) + 4 bytes data = 12 bytes
    EXPECT_EQ(serialized.size(), 12u);

    common::ByteStreamReader reader(serialized);
    auto decoded_opt = DiameterAvp::decode(reader);
    ASSERT_TRUE(decoded_opt.has_value());
    EXPECT_EQ(decoded_opt->code, AVP_RESULT_CODE);
    EXPECT_EQ(decoded_opt->to_unsigned32(), 2001u);
}

TEST(DiameterAvpTest, StringAndPadding) {
    // 5-byte string: "hello" -> 8 byte header + 5 bytes data = 13 bytes.
    // Padded to next multiple of 4 = 16 bytes.
    auto avp = DiameterAvp::create_string(AVP_ORIGIN_HOST, "hello");
    EXPECT_EQ(avp.to_string(), "hello");

    auto serialized = avp.serialize();
    EXPECT_EQ(serialized.size(), 16u);

    common::ByteStreamReader reader(serialized);
    auto decoded_opt = DiameterAvp::decode(reader);
    ASSERT_TRUE(decoded_opt.has_value());
    EXPECT_EQ(decoded_opt->code, AVP_ORIGIN_HOST);
    EXPECT_EQ(decoded_opt->to_string(), "hello");
    EXPECT_EQ(reader.remaining(), 0u);
}

TEST(DiameterAvpTest, VendorSpecificAvp) {
    // TS 29.272 Visited-PLMN-Id (AVP 1400, Vendor 10415)
    std::vector<uint8_t> plmn = {0x00, 0xF1, 0x10}; // MCC 001, MNC 01
    auto avp = DiameterAvp::create_octet_string(AVP_VISITED_PLMN_ID, plmn, true, VENDOR_3GPP);

    EXPECT_TRUE(avp.is_vendor_specific());
    EXPECT_EQ(avp.vendor_id, VENDOR_3GPP);

    auto serialized = avp.serialize();
    // 12 bytes header (vendor) + 3 bytes data = 15 bytes -> padded to 16 bytes
    EXPECT_EQ(serialized.size(), 16u);

    common::ByteStreamReader reader(serialized);
    auto decoded_opt = DiameterAvp::decode(reader);
    ASSERT_TRUE(decoded_opt.has_value());
    EXPECT_EQ(decoded_opt->code, AVP_VISITED_PLMN_ID);
    EXPECT_TRUE(decoded_opt->is_vendor_specific());
    EXPECT_EQ(decoded_opt->vendor_id, VENDOR_3GPP);
    EXPECT_EQ(decoded_opt->to_octet_string(), plmn);
}

TEST(DiameterAvpTest, GroupedAvp) {
    std::vector<DiameterAvp> children;
    children.push_back(DiameterAvp::create_unsigned32(AVP_NUMBER_OF_REQ_VECTORS, 2, true, VENDOR_3GPP));
    children.push_back(DiameterAvp::create_unsigned32(AVP_IMMEDIATE_RESPONSE_PREF, 1, false, VENDOR_3GPP));

    auto parent = DiameterAvp::create_grouped(AVP_REQ_EUTRAN_AUTH_INFO, children, true, VENDOR_3GPP);
    EXPECT_TRUE(parent.is_vendor_specific());

    auto serialized = parent.serialize();
    common::ByteStreamReader reader(serialized);
    auto decoded_opt = DiameterAvp::decode(reader);
    ASSERT_TRUE(decoded_opt.has_value());

    auto unpacked = decoded_opt->to_grouped();
    ASSERT_EQ(unpacked.size(), 2u);
    EXPECT_EQ(unpacked[0].code, AVP_NUMBER_OF_REQ_VECTORS);
    EXPECT_EQ(unpacked[0].to_unsigned32(), 2u);
    EXPECT_EQ(unpacked[1].code, AVP_IMMEDIATE_RESPONSE_PREF);
    EXPECT_EQ(unpacked[1].to_unsigned32(), 1u);
}

TEST(DiameterMessageTest, CapabilitiesExchangeRoundTrip) {
    ip::Ipv4Address host_ip = ip::Ipv4Address::from_string("10.0.0.1");
    auto cer = DiameterFactory::create_cer(
        "mme01.epc.example.org",
        "epc.example.org",
        host_ip,
        10415,
        "OpenEPC-MME",
        {APP_3GPP_S6A},
        1234,
        5678
    );

    EXPECT_TRUE(cer.is_request());
    EXPECT_EQ(cer.command_code, CMD_CAPABILITIES_EXCHANGE);
    EXPECT_EQ(cer.application_id, APP_DIAMETER_COMMON);
    EXPECT_EQ(cer.hop_by_hop_id, 1234u);
    EXPECT_EQ(cer.end_to_end_id, 5678u);

    auto serialized = cer.serialize();
    EXPECT_GE(serialized.size(), DIAMETER_HEADER_SIZE);
    EXPECT_EQ(serialized.size() % 4, 0u);

    auto decoded_opt = DiameterMessage::decode(serialized.data(), serialized.size());
    ASSERT_TRUE(decoded_opt.has_value());
    EXPECT_EQ(decoded_opt->command_code, CMD_CAPABILITIES_EXCHANGE);
    EXPECT_TRUE(decoded_opt->is_request());

    const auto* origin_host = decoded_opt->find_avp(AVP_ORIGIN_HOST);
    ASSERT_NE(origin_host, nullptr);
    EXPECT_EQ(origin_host->to_string(), "mme01.epc.example.org");

    const auto* app_id_avp = decoded_opt->find_avp(AVP_AUTH_APPLICATION_ID);
    ASSERT_NE(app_id_avp, nullptr);
    EXPECT_EQ(app_id_avp->to_unsigned32(), APP_3GPP_S6A);

    // Answer CEA
    auto cea = DiameterFactory::create_cea(
        *decoded_opt,
        DIAMETER_SUCCESS,
        "hss01.epc.example.org",
        "epc.example.org",
        host_ip,
        10415,
        "OpenEPC-HSS",
        {APP_3GPP_S6A}
    );

    EXPECT_FALSE(cea.is_request());
    EXPECT_EQ(cea.hop_by_hop_id, 1234u);
    EXPECT_EQ(cea.end_to_end_id, 5678u);

    const auto* result_code_avp = cea.find_avp(AVP_RESULT_CODE);
    ASSERT_NE(result_code_avp, nullptr);
    EXPECT_EQ(result_code_avp->to_unsigned32(), DIAMETER_SUCCESS);
}

TEST(DiameterMessageTest, WatchdogRoundTrip) {
    auto dwr = DiameterFactory::create_dwr("client.realm", "realm", 99, 100);
    EXPECT_TRUE(dwr.is_request());
    EXPECT_EQ(dwr.command_code, CMD_DEVICE_WATCHDOG);

    auto serialized = dwr.serialize();
    auto decoded_opt = DiameterMessage::decode(serialized.data(), serialized.size());
    ASSERT_TRUE(decoded_opt.has_value());

    auto dwa = DiameterFactory::create_dwa(*decoded_opt, DIAMETER_SUCCESS, "server.realm", "realm");
    EXPECT_FALSE(dwa.is_request());
    EXPECT_EQ(dwa.hop_by_hop_id, 99u);
    EXPECT_EQ(dwa.end_to_end_id, 100u);

    const auto* rc = dwa.find_avp(AVP_RESULT_CODE);
    ASSERT_NE(rc, nullptr);
    EXPECT_EQ(rc->to_unsigned32(), 2001u);
}

TEST(DiameterS6aTest, AirAiaAuthenticationVectors) {
    std::string session_id = "mme.epc.mnc001.mcc001.3gppnetwork.org;1700000000;1";
    std::vector<uint8_t> visited_plmn = {0x00, 0xF1, 0x10};
    std::string imsi = "001010123456789";

    auto air = DiameterFactory::create_s6a_air(
        session_id,
        "mme01.epc.example.org",
        "epc.example.org",
        "hss.epc.example.org",
        imsi,
        visited_plmn,
        1,
        5001,
        6001
    );

    EXPECT_EQ(air.command_code, CMD_AUTHENTICATION_INFO);
    EXPECT_EQ(air.application_id, APP_3GPP_S6A);
    EXPECT_TRUE(air.is_request());
    EXPECT_TRUE(air.is_proxiable());

    auto serialized_air = air.serialize();
    auto decoded_air_opt = DiameterMessage::decode(serialized_air.data(), serialized_air.size());
    ASSERT_TRUE(decoded_air_opt.has_value());

    const auto* imsi_avp = decoded_air_opt->find_avp(AVP_USER_NAME);
    ASSERT_NE(imsi_avp, nullptr);
    EXPECT_EQ(imsi_avp->to_string(), imsi);

    // Prepare AIA with EPS Authentication Vector (RAND, XRES, AUTN, KASME)
    EutranVector vec;
    vec.rand = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    vec.xres = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
    vec.autn = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    vec.kasme.resize(32, 0x5A); // 256-bit key

    auto aia = DiameterFactory::create_s6a_aia(
        *decoded_air_opt,
        DIAMETER_SUCCESS,
        "hss01.epc.example.org",
        "epc.example.org",
        {vec}
    );

    EXPECT_FALSE(aia.is_request());
    EXPECT_EQ(aia.command_code, CMD_AUTHENTICATION_INFO);
    EXPECT_EQ(aia.application_id, APP_3GPP_S6A);

    auto serialized_aia = aia.serialize();
    auto decoded_aia_opt = DiameterMessage::decode(serialized_aia.data(), serialized_aia.size());
    ASSERT_TRUE(decoded_aia_opt.has_value());

    const auto* auth_info = decoded_aia_opt->find_avp(AVP_AUTHENTICATION_INFO, VENDOR_3GPP);
    ASSERT_NE(auth_info, nullptr);

    auto auth_info_children = auth_info->to_grouped();
    ASSERT_EQ(auth_info_children.size(), 1u);
    EXPECT_EQ(auth_info_children[0].code, AVP_E_UTRAN_VECTOR);

    auto vector_elements = auth_info_children[0].to_grouped();
    bool found_rand = false, found_xres = false, found_autn = false, found_kasme = false;
    for (const auto& elem : vector_elements) {
        if (elem.code == AVP_RAND) {
            EXPECT_EQ(elem.to_octet_string(), vec.rand);
            found_rand = true;
        } else if (elem.code == AVP_XRES) {
            EXPECT_EQ(elem.to_octet_string(), vec.xres);
            found_xres = true;
        } else if (elem.code == AVP_AUTN) {
            EXPECT_EQ(elem.to_octet_string(), vec.autn);
            found_autn = true;
        } else if (elem.code == AVP_KASME) {
            EXPECT_EQ(elem.to_octet_string(), vec.kasme);
            found_kasme = true;
        }
    }
    EXPECT_TRUE(found_rand);
    EXPECT_TRUE(found_xres);
    EXPECT_TRUE(found_autn);
    EXPECT_TRUE(found_kasme);
}

TEST(DiameterConnectionTest, LoopbackCERExchange) {
    ip::TcpListener listener;
    ASSERT_TRUE(listener.listen("127.0.0.1", 0));
    uint16_t port = listener.local_port();

    std::thread server_thread([&listener, port]() {
        ip::TcpSocket client_sock;
        std::string client_host;
        uint16_t client_port;
        if (listener.accept(client_sock, client_host, client_port, 2000)) {
            DiameterConnection conn(std::make_unique<ip::TcpSocket>(std::move(client_sock)));
            auto req_opt = conn.receive_message(std::chrono::milliseconds(2000));
            if (req_opt.has_value() && req_opt->command_code == CMD_CAPABILITIES_EXCHANGE) {
                auto cea = DiameterFactory::create_cea(
                    *req_opt,
                    DIAMETER_SUCCESS,
                    "server.local",
                    "local",
                    ip::Ipv4Address::Loopback,
                    VENDOR_3GPP,
                    "MockServer",
                    {APP_3GPP_S6A}
                );
                conn.send_message(cea);
            }
        }
    });

    auto client_sock = std::make_unique<ip::TcpSocket>();
    ASSERT_TRUE(client_sock->connect("127.0.0.1", port, 2000));
    DiameterConnection client_conn(std::move(client_sock));

    auto cer = DiameterFactory::create_cer(
        "client.local",
        "local",
        ip::Ipv4Address::Loopback,
        VENDOR_3GPP,
        "MockClient",
        {APP_3GPP_S6A}
    );
    ASSERT_TRUE(client_conn.send_message(cer));

    auto answer_opt = client_conn.receive_message(std::chrono::milliseconds(2000));
    ASSERT_TRUE(answer_opt.has_value());
    EXPECT_EQ(answer_opt->command_code, CMD_CAPABILITIES_EXCHANGE);
    const auto* rc = answer_opt->find_avp(AVP_RESULT_CODE);
    ASSERT_NE(rc, nullptr);
    EXPECT_EQ(rc->to_unsigned32(), DIAMETER_SUCCESS);

    server_thread.join();
}
