#include <gtest/gtest.h>
#include <3gpp/nr_nas/NrNasCommon.hpp>
#include <3gpp/nr_nas/NrNasIe.hpp>
#include <3gpp/nr_nas/GmmMessage.hpp>
#include <3gpp/nr_nas/GsmMessage.hpp>

using namespace gpp::nr_nas;

// ─── Header Tests ───────────────────────────────────────────────────────────

TEST(NrNasTest, GmmHeaderEncodeDecode) {
    NrNasHeader hdr;
    hdr.epd = ExtendedProtocolDiscriminator::GMM;
    hdr.security_header_type = SecurityHeaderType::PlainNas;
    hdr.message_type = static_cast<uint8_t>(GmmMessageType::RegistrationRequest);

    auto enc = hdr.encode();
    ASSERT_EQ(enc.size(), 3u);
    EXPECT_EQ(enc[0], 0x7E); // EPD = 5GMM
    EXPECT_EQ(enc[1], 0x00); // SHT = Plain NAS
    EXPECT_EQ(enc[2], 0x41); // RegistrationRequest

    size_t offset = 0;
    auto dec = NrNasHeader::decode(enc, offset);
    EXPECT_EQ(dec.epd, ExtendedProtocolDiscriminator::GMM);
    EXPECT_EQ(dec.security_header_type, SecurityHeaderType::PlainNas);
    EXPECT_EQ(dec.message_type, static_cast<uint8_t>(GmmMessageType::RegistrationRequest));
    EXPECT_EQ(offset, 3u);
}

TEST(NrNasTest, GsmHeaderEncodeDecode) {
    NrGsmHeader hdr;
    hdr.epd = ExtendedProtocolDiscriminator::GSM;
    hdr.pdu_session_id = 1;
    hdr.procedure_transaction_id = 5;
    hdr.message_type = static_cast<uint8_t>(GsmMessageType::PduSessionEstablishmentRequest);

    auto enc = hdr.encode();
    ASSERT_EQ(enc.size(), 4u);
    EXPECT_EQ(enc[0], 0x2E); // EPD = 5GSM
    EXPECT_EQ(enc[1], 1u);   // PSI
    EXPECT_EQ(enc[2], 5u);   // PTI
    EXPECT_EQ(enc[3], 0xC1); // PduSessionEstablishmentRequest

    size_t offset = 0;
    auto dec = NrGsmHeader::decode(enc, offset);
    EXPECT_EQ(dec.epd, ExtendedProtocolDiscriminator::GSM);
    EXPECT_EQ(dec.pdu_session_id, 1u);
    EXPECT_EQ(dec.procedure_transaction_id, 5u);
    EXPECT_EQ(dec.message_type, static_cast<uint8_t>(GsmMessageType::PduSessionEstablishmentRequest));
    EXPECT_EQ(offset, 4u);
}

// ─── SUCI Tests ─────────────────────────────────────────────────────────────

TEST(NrNasTest, SuciEncodingDecoding) {
    Suci s;
    s.mcc = "001";
    s.mnc = "01";
    s.routing_indicator = 0;
    s.protection_scheme = 0; // Null-scheme
    s.home_network_pki = 0;
    s.msin = "0123456789";

    auto enc = s.encode();
    ASSERT_GE(enc.size(), 10u);

    size_t offset = 0;
    auto dec = Suci::decode(enc, offset);
    EXPECT_EQ(dec.mcc, "001");
    EXPECT_EQ(dec.mnc, "01");
    EXPECT_EQ(dec.routing_indicator, 0u);
    EXPECT_EQ(dec.protection_scheme, 0u);
    EXPECT_EQ(dec.msin, "0123456789");
    EXPECT_EQ(offset, enc.size());
}

// ─── 5G-GUTI Tests ──────────────────────────────────────────────────────────

TEST(NrNasTest, NrGutiEncodingDecoding) {
    NrGuti g;
    g.mcc = "001";
    g.mnc = "01";
    g.amf_region_id = 0x12;
    g.amf_set_id = 0x01AA;
    g.amf_pointer = 0x2B;
    g.tmsi = 0xDEADBEEF;

    auto enc = g.encode();
    ASSERT_EQ(enc.size(), 13u);
    EXPECT_EQ(enc[0], 0x77); // IEI
    EXPECT_EQ(enc[1], 11u);  // length

    size_t offset = 0;
    auto dec = NrGuti::decode(enc, offset);
    EXPECT_EQ(dec.mcc, "001");
    EXPECT_EQ(dec.mnc, "01");
    EXPECT_EQ(dec.amf_region_id, 0x12u);
    EXPECT_EQ(dec.amf_set_id, 0x01AAu);
    EXPECT_EQ(dec.amf_pointer, 0x2Bu);
    EXPECT_EQ(dec.tmsi, 0xDEADBEEFu);
    EXPECT_EQ(offset, 13u);
}

// ─── S-NSSAI Tests ──────────────────────────────────────────────────────────

TEST(NrNasTest, SNssaiEncodingDecoding) {
    // With SD
    SNssai s1;
    s1.sst = 1; // eMBB
    s1.sd = 0x000001;

    auto enc1 = s1.encode();
    ASSERT_EQ(enc1.size(), 5u);
    EXPECT_EQ(enc1[0], 4u); // length
    EXPECT_EQ(enc1[1], 1u); // SST

    auto dec1 = SNssai::decode(enc1);
    EXPECT_EQ(dec1.sst, 1u);
    ASSERT_TRUE(dec1.sd.has_value());
    EXPECT_EQ(*dec1.sd, 0x000001u);

    // Without SD
    SNssai s2;
    s2.sst = 2; // URLLC
    s2.sd = std::nullopt;

    auto enc2 = s2.encode();
    ASSERT_EQ(enc2.size(), 2u);
    EXPECT_EQ(enc2[0], 1u); // length
    EXPECT_EQ(enc2[1], 2u); // SST

    auto dec2 = SNssai::decode(enc2);
    EXPECT_EQ(dec2.sst, 2u);
    EXPECT_FALSE(dec2.sd.has_value());
}

// ─── 5GMM Registration Request Round-Trip ───────────────────────────────────

TEST(GmmTest, RegistrationRequestRoundTrip) {
    PduSessionEstablishmentRequest pdu_req;
    pdu_req.pdu_session_id = 1;
    pdu_req.procedure_transaction_id = 1;
    pdu_req.session_type = PduSessionType::Ipv4;
    pdu_req.ssc_mode = SscMode::Mode1;
    pdu_req.s_nssai.sst = 1;
    pdu_req.s_nssai.sd = 0x000001;
    pdu_req.dnn.dnn = "internet";
    auto gsm_bytes = pdu_req.encode();

    RegistrationRequest req;
    req.registration_type = 0x01;
    req.ng_ksi = 0x07;
    req.suci.mcc = "001";
    req.suci.mnc = "01";
    req.suci.msin = "0123456789";
    req.ue_security_capability = {0x80, 0x20, 0x00};
    req.requested_nssai.push_back(pdu_req.s_nssai);
    req.gsm_message_container = gsm_bytes;

    auto enc = req.encode();
    ASSERT_FALSE(enc.empty());

    auto dec = RegistrationRequest::decode(enc);
    EXPECT_EQ(dec.registration_type, 0x01u);
    EXPECT_EQ(dec.ng_ksi, 0x07u);
    EXPECT_EQ(dec.suci.mcc, "001");
    EXPECT_EQ(dec.suci.msin, "0123456789");
    EXPECT_EQ(dec.ue_security_capability, req.ue_security_capability);
    ASSERT_EQ(dec.requested_nssai.size(), 1u);
    EXPECT_EQ(dec.requested_nssai[0].sst, 1u);
    EXPECT_EQ(dec.gsm_message_container, gsm_bytes);
}

// ─── 5GMM Registration Accept Round-Trip ────────────────────────────────────

TEST(GmmTest, RegistrationAcceptRoundTrip) {
    PduSessionEstablishmentAccept pdu_acc;
    pdu_acc.pdu_session_id = 1;
    pdu_acc.procedure_transaction_id = 1;
    pdu_acc.session_type = PduSessionType::Ipv4;
    pdu_acc.ssc_mode = SscMode::Mode1;
    pdu_acc.qos_rule.qfi = 1;
    pdu_acc.qos_rule.five_qi = 9;
    pdu_acc.pdu_address.pdu_type = 0x01;
    pdu_acc.pdu_address.ipv4 = {10, 45, 0, 2};
    pdu_acc.s_nssai.sst = 1;
    pdu_acc.s_nssai.sd = 0x000001;
    pdu_acc.dnn.dnn = "internet";
    auto gsm_bytes = pdu_acc.encode();

    RegistrationAccept acc;
    acc.registration_result = 0x01;
    acc.guti.mcc = "001";
    acc.guti.mnc = "01";
    acc.guti.amf_region_id = 1;
    acc.guti.amf_set_id = 1;
    acc.guti.amf_pointer = 1;
    acc.guti.tmsi = 0xABCD1234;
    acc.t3512_value = 0x21;
    acc.allowed_nssai.push_back(pdu_acc.s_nssai);
    acc.gsm_message_container = gsm_bytes;

    auto enc = acc.encode();
    ASSERT_FALSE(enc.empty());

    auto dec = RegistrationAccept::decode(enc);
    EXPECT_EQ(dec.registration_result, 0x01u);
    EXPECT_EQ(dec.guti.tmsi, 0xABCD1234u);
    EXPECT_EQ(dec.t3512_value, 0x21u);
    ASSERT_EQ(dec.allowed_nssai.size(), 1u);
    EXPECT_EQ(dec.allowed_nssai[0].sst, 1u);
    EXPECT_EQ(dec.gsm_message_container, gsm_bytes);
}

// ─── 5GSM PDU Session Establishment Round-Trip ──────────────────────────────

TEST(GsmTest, PduSessionEstablishmentRequestRoundTrip) {
    PduSessionEstablishmentRequest req;
    req.pdu_session_id = 1;
    req.procedure_transaction_id = 2;
    req.session_type = PduSessionType::Ipv4;
    req.ssc_mode = SscMode::Mode1;
    req.s_nssai.sst = 1;
    req.s_nssai.sd = 0x000001;
    req.dnn.dnn = "ims";

    auto enc = req.encode();
    ASSERT_FALSE(enc.empty());

    auto dec = PduSessionEstablishmentRequest::decode(enc);
    EXPECT_EQ(dec.pdu_session_id, 1u);
    EXPECT_EQ(dec.procedure_transaction_id, 2u);
    EXPECT_EQ(dec.session_type, PduSessionType::Ipv4);
    EXPECT_EQ(dec.ssc_mode, SscMode::Mode1);
    EXPECT_EQ(dec.s_nssai.sst, 1u);
    EXPECT_EQ(dec.dnn.dnn, "ims");
}

TEST(GsmTest, PduSessionEstablishmentAcceptRoundTrip) {
    PduSessionEstablishmentAccept acc;
    acc.pdu_session_id = 1;
    acc.procedure_transaction_id = 2;
    acc.session_type = PduSessionType::Ipv4;
    acc.ssc_mode = SscMode::Mode1;
    acc.qos_rule.qfi = 1;
    acc.qos_rule.five_qi = 5; // IMS signaling
    acc.pdu_address.pdu_type = 0x01;
    acc.pdu_address.ipv4 = {10, 45, 0, 5};
    acc.s_nssai.sst = 1;
    acc.s_nssai.sd = 0x000001;
    acc.dnn.dnn = "ims";

    auto enc = acc.encode();
    ASSERT_FALSE(enc.empty());

    auto dec = PduSessionEstablishmentAccept::decode(enc);
    EXPECT_EQ(dec.pdu_session_id, 1u);
    EXPECT_EQ(dec.procedure_transaction_id, 2u);
    EXPECT_EQ(dec.qos_rule.qfi, 1u);
    EXPECT_EQ(dec.qos_rule.five_qi, 5u);
    EXPECT_EQ(dec.pdu_address.ipv4[3], 5u);
    EXPECT_EQ(dec.dnn.dnn, "ims");
}

TEST(GsmTest, PduSessionEstablishmentReject) {
    PduSessionEstablishmentReject rej;
    rej.pdu_session_id = 1;
    rej.procedure_transaction_id = 3;
    rej.gsm_cause = 0x1B; // Missing or unknown DNN

    auto enc = rej.encode();
    ASSERT_EQ(enc.size(), 5u);

    auto dec = PduSessionEstablishmentReject::decode(enc);
    EXPECT_EQ(dec.pdu_session_id, 1u);
    EXPECT_EQ(dec.procedure_transaction_id, 3u);
    EXPECT_EQ(dec.gsm_cause, 0x1Bu);
}

// ─── Integration: Full UE ↔ AMF Registration Exchange ───────────────────────

TEST(NrNasIntegrationTest, UeAmfLoopbackRegistration) {
    // 1. UE encodes PduSessionEstablishmentRequest
    PduSessionEstablishmentRequest pdu_req;
    pdu_req.pdu_session_id = 1;
    pdu_req.procedure_transaction_id = 1;
    pdu_req.session_type = PduSessionType::Ipv4;
    pdu_req.ssc_mode = SscMode::Mode1;
    pdu_req.s_nssai.sst = 1;
    pdu_req.s_nssai.sd = 0x000001;
    pdu_req.dnn.dnn = "internet";

    RegistrationRequest reg_req;
    reg_req.registration_type = 0x01;
    reg_req.ng_ksi = 0x07;
    reg_req.suci.mcc = "001";
    reg_req.suci.mnc = "01";
    reg_req.suci.msin = "0123456789";
    reg_req.ue_security_capability = {0x80, 0x20};
    reg_req.requested_nssai.push_back(pdu_req.s_nssai);
    reg_req.gsm_message_container = pdu_req.encode();

    auto wire_reg_req = reg_req.encode();

    // 2. AMF decodes RegistrationRequest
    auto amf_rx_req = RegistrationRequest::decode(wire_reg_req);
    EXPECT_EQ(amf_rx_req.suci.msin, "0123456789");

    auto amf_rx_pdu_req = PduSessionEstablishmentRequest::decode(amf_rx_req.gsm_message_container);
    EXPECT_EQ(amf_rx_pdu_req.dnn.dnn, "internet");

    // 3. AMF generates RegistrationAccept + PduSessionEstablishmentAccept
    PduSessionEstablishmentAccept pdu_acc;
    pdu_acc.pdu_session_id = amf_rx_pdu_req.pdu_session_id;
    pdu_acc.procedure_transaction_id = amf_rx_pdu_req.procedure_transaction_id;
    pdu_acc.session_type = PduSessionType::Ipv4;
    pdu_acc.ssc_mode = SscMode::Mode1;
    pdu_acc.qos_rule.qfi = 1;
    pdu_acc.qos_rule.five_qi = 9;
    pdu_acc.pdu_address.pdu_type = 0x01;
    pdu_acc.pdu_address.ipv4 = {10, 45, 0, 2};
    pdu_acc.s_nssai = amf_rx_pdu_req.s_nssai;
    pdu_acc.dnn = amf_rx_pdu_req.dnn;

    RegistrationAccept reg_acc;
    reg_acc.registration_result = 0x01;
    reg_acc.guti.mcc = "001";
    reg_acc.guti.mnc = "01";
    reg_acc.guti.amf_region_id = 1;
    reg_acc.guti.amf_set_id = 1;
    reg_acc.guti.amf_pointer = 1;
    reg_acc.guti.tmsi = 0x5678ABCD;
    reg_acc.t3512_value = 0x21;
    reg_acc.allowed_nssai.push_back(pdu_acc.s_nssai);
    reg_acc.gsm_message_container = pdu_acc.encode();

    auto wire_reg_acc = reg_acc.encode();

    // 4. UE decodes RegistrationAccept
    auto ue_rx_acc = RegistrationAccept::decode(wire_reg_acc);
    EXPECT_EQ(ue_rx_acc.guti.tmsi, 0x5678ABCDu);

    auto ue_rx_pdu_acc = PduSessionEstablishmentAccept::decode(ue_rx_acc.gsm_message_container);
    EXPECT_EQ(ue_rx_pdu_acc.pdu_address.ipv4[0], 10u);
    EXPECT_EQ(ue_rx_pdu_acc.pdu_address.ipv4[3], 2u);

    // 5. UE generates RegistrationComplete
    RegistrationComplete reg_comp;
    auto wire_reg_comp = reg_comp.encode();
    ASSERT_GE(wire_reg_comp.size(), 3u);
    EXPECT_EQ(wire_reg_comp[0], 0x7E); // EPD
    EXPECT_EQ(wire_reg_comp[2], static_cast<uint8_t>(GmmMessageType::RegistrationComplete));
}
