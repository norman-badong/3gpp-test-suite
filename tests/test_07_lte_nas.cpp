#include <gtest/gtest.h>
#include <3gpp/lte_nas/NasCommon.hpp>
#include <3gpp/lte_nas/NasIe.hpp>
#include <3gpp/lte_nas/EmmMessage.hpp>
#include <3gpp/lte_nas/EsmMessage.hpp>

using namespace gpp::lte_nas;

// ─── NasHeader tests ────────────────────────────────────────────────────────

TEST(NasTest, HeaderEncodeDecode) {
    NasHeader hdr;
    hdr.security_header_type = SecurityHeaderType::PlainNas;
    hdr.protocol_discriminator = ProtocolDiscriminator::EMM;
    hdr.message_type = static_cast<uint8_t>(EmmMessageType::AttachRequest);

    auto enc = hdr.encode();
    ASSERT_EQ(enc.size(), 2u);
    EXPECT_EQ(enc[0], 0x07); // SHT=0 << 4 | PD=7
    EXPECT_EQ(enc[1], 0x41); // AttachRequest

    size_t offset = 0;
    auto dec = NasHeader::decode(enc, offset);
    EXPECT_EQ(dec.security_header_type, SecurityHeaderType::PlainNas);
    EXPECT_EQ(dec.protocol_discriminator, ProtocolDiscriminator::EMM);
    EXPECT_EQ(dec.message_type, static_cast<uint8_t>(EmmMessageType::AttachRequest));
    EXPECT_EQ(offset, 2u);
}

// ─── IMSI encoding tests ─────────────────────────────────────────────────────

TEST(NasTest, ImsiMobileIdentityEncoding) {
    MobileIdentity mi;
    mi.imsi = "001010123456789";

    auto lv = mi.encode();
    // length byte + 8 value bytes = 9 total
    ASSERT_EQ(lv.size(), 9u);
    EXPECT_EQ(lv[0], 8u);   // length
    EXPECT_EQ(lv[1], 0x09); // digit1=0, odd=1, type=001
    EXPECT_EQ(lv[2], 0x10); // digit3=1 | digit2=0
    EXPECT_EQ(lv[3], 0x10); // digit5=1 | digit4=0
    EXPECT_EQ(lv[4], 0x10); // digit7=1 | digit6=0
    EXPECT_EQ(lv[5], 0x32); // digit9=3 | digit8=2
    EXPECT_EQ(lv[6], 0x54); // digit11=5 | digit10=4
    EXPECT_EQ(lv[7], 0x76); // digit13=7 | digit12=6
    EXPECT_EQ(lv[8], 0x98); // digit15=9 | digit14=8

    auto decoded = MobileIdentity::decode_imsi(lv);
    EXPECT_EQ(decoded.imsi, "001010123456789");
}

// ─── GUTI tests ──────────────────────────────────────────────────────────────

TEST(NasTest, GutiEncoding) {
    Guti g;
    g.mcc = "001";
    g.mnc = "01";
    g.mme_group_id = 1;
    g.mme_code = 1;
    g.m_tmsi = 0x12345678;

    auto tlv = g.encode();
    ASSERT_GE(tlv.size(), 2u);
    EXPECT_EQ(tlv[0], 0x50); // IEI

    size_t offset = 0;
    auto decoded = Guti::decode(tlv, offset);
    EXPECT_EQ(decoded.mcc, "001");
    EXPECT_EQ(decoded.mnc, "01");
    EXPECT_EQ(decoded.mme_group_id, 1u);
    EXPECT_EQ(decoded.mme_code, 1u);
    EXPECT_EQ(decoded.m_tmsi, 0x12345678u);
}

// ─── TAI List tests ───────────────────────────────────────────────────────────

TEST(NasTest, TaiListEncoding) {
    TaiList tai;
    tai.mcc = "001";
    tai.mnc = "01";
    tai.tacs = {0x1234};

    auto lv = tai.encode();
    ASSERT_GE(lv.size(), 2u); // at least length + 1 byte

    auto decoded = TaiList::decode(lv);
    EXPECT_EQ(decoded.mcc, "001");
    EXPECT_EQ(decoded.mnc, "01");
    ASSERT_EQ(decoded.tacs.size(), 1u);
    EXPECT_EQ(decoded.tacs[0], 0x1234u);
}

// ─── EMM Attach Request round-trip ───────────────────────────────────────────

TEST(EmmTest, AttachRequestRoundTrip) {
    PdnConnectivityRequest pdn;
    pdn.eps_bearer_id = 0;
    pdn.procedure_transaction_id = 1;
    pdn.pdn_type = 0x01;
    pdn.request_type = 0x01;
    auto esm_bytes = pdn.encode();

    AttachRequest req;
    req.eps_attach_type = 0x01;
    req.nas_key_set_id  = 0x07;
    req.mobile_id.imsi  = "001010123456789";
    req.ue_network_capability = {0xE0, 0x00, 0x00, 0x00};
    req.esm_message_container = esm_bytes;

    auto enc = req.encode();
    ASSERT_FALSE(enc.empty());

    auto dec = AttachRequest::decode(enc);
    EXPECT_EQ(dec.mobile_id.imsi, "001010123456789");
    EXPECT_EQ(dec.eps_attach_type, 0x01u);
    EXPECT_EQ(dec.nas_key_set_id, 0x07u);
    EXPECT_EQ(dec.ue_network_capability, req.ue_network_capability);
    EXPECT_EQ(dec.esm_message_container, esm_bytes);
}

// ─── EMM Attach Accept round-trip ─────────────────────────────────────────────

TEST(EmmTest, AttachAcceptRoundTrip) {
    ActivateDefaultEpsBearerContextRequest bearer;
    bearer.eps_bearer_id = 5;
    bearer.procedure_transaction_id = 1;
    bearer.qos.qci = 9;
    bearer.apn.apn = "internet";
    bearer.pdn_address.pdn_type = 0x01;
    bearer.pdn_address.ipv4 = {10, 45, 0, 1};
    auto esm_bytes = bearer.encode();

    AttachAccept accept;
    accept.eps_attach_result = 0x01;
    accept.t3412_value = 0x21;
    accept.tai_list.mcc = "001";
    accept.tai_list.mnc = "01";
    accept.tai_list.tacs = {0x1234};
    accept.esm_message_container = esm_bytes;
    accept.guti.mcc = "001";
    accept.guti.mnc = "01";
    accept.guti.mme_group_id = 1;
    accept.guti.mme_code = 1;
    accept.guti.m_tmsi = 0xABCD1234;

    auto enc = accept.encode();
    ASSERT_FALSE(enc.empty());

    auto dec = AttachAccept::decode(enc);
    EXPECT_EQ(dec.eps_attach_result, 0x01u);
    EXPECT_EQ(dec.t3412_value, 0x21u);
    EXPECT_EQ(dec.tai_list.mcc, "001");
    ASSERT_FALSE(dec.tai_list.tacs.empty());
    EXPECT_EQ(dec.tai_list.tacs[0], 0x1234u);
    EXPECT_EQ(dec.guti.m_tmsi, 0xABCD1234u);
    EXPECT_EQ(dec.esm_message_container, esm_bytes);
}

// ─── ESM PDN Connectivity round-trip ─────────────────────────────────────────

TEST(EsmTest, PdnConnectivityRequestRoundTrip) {
    PdnConnectivityRequest req;
    req.eps_bearer_id = 0;
    req.procedure_transaction_id = 1;
    req.pdn_type = 0x01;
    req.request_type = 0x01;

    auto enc = req.encode();
    ASSERT_FALSE(enc.empty());

    auto dec = PdnConnectivityRequest::decode(enc);
    EXPECT_EQ(dec.eps_bearer_id, 0u);
    EXPECT_EQ(dec.procedure_transaction_id, 1u);
    EXPECT_EQ(dec.pdn_type, 0x01u);
    EXPECT_EQ(dec.request_type, 0x01u);
}

// ─── ESM Activate Default Bearer round-trip ──────────────────────────────────

TEST(EsmTest, ActivateDefaultBearerRoundTrip) {
    ActivateDefaultEpsBearerContextRequest req;
    req.eps_bearer_id = 5;
    req.procedure_transaction_id = 1;
    req.qos.qci = 9;
    req.apn.apn = "internet";
    req.pdn_address.pdn_type = 0x01;
    req.pdn_address.ipv4 = {10, 0, 0, 1};

    auto enc = req.encode();
    ASSERT_FALSE(enc.empty());

    auto dec = ActivateDefaultEpsBearerContextRequest::decode(enc);
    EXPECT_EQ(dec.eps_bearer_id, 5u);
    EXPECT_EQ(dec.qos.qci, 9u);
    EXPECT_EQ(dec.apn.apn, "internet");
    EXPECT_EQ(dec.pdn_address.pdn_type, 0x01u);
    EXPECT_EQ(dec.pdn_address.ipv4[0], 10u);
}

// ─── Integration: full UE↔MME loopback ───────────────────────────────────────

TEST(NasIntegrationTest, UeMmeLoopbackAttach) {
    // UE side: build attach request
    PdnConnectivityRequest pdn_req;
    pdn_req.eps_bearer_id = 0;
    pdn_req.procedure_transaction_id = 1;
    pdn_req.pdn_type = 0x01;
    pdn_req.request_type = 0x01;

    AttachRequest attach_req;
    attach_req.eps_attach_type  = 0x01;
    attach_req.nas_key_set_id   = 0x07;
    attach_req.mobile_id.imsi   = "001010123456789";
    attach_req.ue_network_capability = {0xE0, 0x00, 0x00, 0x00};
    attach_req.esm_message_container = pdn_req.encode();

    auto wire_attach_req = attach_req.encode();

    // MME side: decode attach request
    auto mme_decoded_req = AttachRequest::decode(wire_attach_req);
    EXPECT_EQ(mme_decoded_req.mobile_id.imsi, "001010123456789");

    // MME: build attach accept with default bearer
    ActivateDefaultEpsBearerContextRequest bearer;
    bearer.eps_bearer_id = 5;
    bearer.procedure_transaction_id = 1;
    bearer.qos.qci = 9;
    bearer.apn.apn = "internet";
    bearer.pdn_address.pdn_type = 0x01;
    bearer.pdn_address.ipv4 = {10, 45, 0, 1};

    AttachAccept attach_accept;
    attach_accept.eps_attach_result = 0x01;
    attach_accept.t3412_value = 0x21;
    attach_accept.tai_list.mcc = "001";
    attach_accept.tai_list.mnc = "01";
    attach_accept.tai_list.tacs = {0x1234};
    attach_accept.esm_message_container = bearer.encode();
    attach_accept.guti.mcc = "001";
    attach_accept.guti.mnc = "01";
    attach_accept.guti.mme_group_id = 1;
    attach_accept.guti.mme_code = 1;
    attach_accept.guti.m_tmsi = 0xDEADBEEF;

    auto wire_attach_accept = attach_accept.encode();

    // UE side: decode attach accept
    auto ue_decoded_accept = AttachAccept::decode(wire_attach_accept);
    EXPECT_EQ(ue_decoded_accept.eps_attach_result, 0x01u);
    EXPECT_EQ(ue_decoded_accept.guti.m_tmsi, 0xDEADBEEFu);

    // UE: decode bearer from ESM container
    auto decoded_bearer = ActivateDefaultEpsBearerContextRequest::decode(
        ue_decoded_accept.esm_message_container);
    EXPECT_EQ(decoded_bearer.pdn_address.ipv4[3], 1u); // 10.45.0.1

    // UE: send attach complete
    ActivateDefaultEpsBearerContextAccept act_accept;
    act_accept.eps_bearer_id = 5;
    act_accept.procedure_transaction_id = 1;

    AttachComplete complete;
    complete.esm_message_container = act_accept.encode();
    auto wire_complete = complete.encode();
    ASSERT_FALSE(wire_complete.empty());

    // Basic sanity: message type byte
    EXPECT_EQ(wire_complete[1], static_cast<uint8_t>(EmmMessageType::AttachComplete));
}
