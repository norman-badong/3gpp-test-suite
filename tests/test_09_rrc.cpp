#include <gtest/gtest.h>
#include <3gpp/rrc/Asn1Aper.hpp>
#include <3gpp/rrc/RrcTypes.hpp>
#include <3gpp/rrc/RrcMessage.hpp>

using namespace gpp::rrc;

// ─── APER Primitives Tests ──────────────────────────────────────────────────

TEST(AperPrimitivesTest, BooleanAndConstrainedInt) {
    AperWriter w;
    w.write_boolean(true);
    w.write_boolean(false);
    w.write_constrained_integer(3, 0, 7);   // 3 bits
    w.write_constrained_integer(15, 0, 15); // 4 bits
    w.align_to_byte();

    auto bytes = w.bytes();
    AperReader r(bytes);
    EXPECT_TRUE(r.read_boolean());
    EXPECT_FALSE(r.read_boolean());
    EXPECT_EQ(r.read_constrained_integer(0, 7), 3);
    EXPECT_EQ(r.read_constrained_integer(0, 15), 15);
}

TEST(AperPrimitivesTest, EnumeratedAndChoice) {
    AperWriter w;
    w.write_enumerated(static_cast<uint32_t>(EstablishmentCause::MoSignalling), 8, false);
    w.write_choice_index(1, 4, false); // Choice index 1 out of 4 (2 bits)
    w.align_to_byte();

    auto bytes = w.bytes();
    AperReader r(bytes);
    EXPECT_EQ(r.read_enumerated(8, false), static_cast<uint32_t>(EstablishmentCause::MoSignalling));
    EXPECT_EQ(r.read_choice_index(4, false), 1u);
}

TEST(AperPrimitivesTest, BitString39Bits) {
    AperWriter w;
    uint64_t val = 0x456789ABCDULL & 0x7FFFFFFFFFULL; // 39 bits
    w.write_bit_string(val, 39);
    w.align_to_byte();

    auto bytes = w.bytes();
    EXPECT_EQ(bytes.size(), 5u); // (39 + 7) / 8 = 5 bytes

    AperReader r(bytes);
    uint64_t read_val = r.read_bit_string(39);
    EXPECT_EQ(read_val, val);
}

TEST(AperPrimitivesTest, OctetStringShortAndLong) {
    std::vector<uint8_t> short_data = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> long_data(200, 0xAA);

    AperWriter w;
    w.write_octet_string(short_data);
    w.write_octet_string(long_data);

    auto bytes = w.bytes();
    AperReader r(bytes);

    auto res_short = r.read_octet_string();
    EXPECT_EQ(res_short, short_data);

    auto res_long = r.read_octet_string();
    EXPECT_EQ(res_long, long_data);
}

// ─── RRC Message Round-Trip Tests ───────────────────────────────────────────

TEST(RrcMessageTest, RrcSetupRequestRoundTrip) {
    RrcSetupRequest req;
    req.ue_identity_type = InitialUeIdentityType::Ng5g_S_TMSI_Part1;
    req.ue_identity_val = 0x123456789AULL & 0x7FFFFFFFFFULL;
    req.establishment_cause = EstablishmentCause::MoSignalling;
    req.spare = false;

    auto enc = req.encode();
    ASSERT_FALSE(enc.empty());

    auto dec = RrcSetupRequest::decode(enc);
    EXPECT_EQ(dec.ue_identity_type, InitialUeIdentityType::Ng5g_S_TMSI_Part1);
    EXPECT_EQ(dec.ue_identity_val, req.ue_identity_val);
    EXPECT_EQ(dec.establishment_cause, EstablishmentCause::MoSignalling);
    EXPECT_FALSE(dec.spare);
}

TEST(RrcMessageTest, RrcSetupRoundTrip) {
    RrcSetup setup;
    setup.rrc_transaction_id = 1;
    setup.srb_identity = 1; // SRB1
    setup.rlc_mode = RlcMode::AM;
    setup.master_cell_group = {0xDE, 0xAD, 0xBE, 0xEF};

    auto enc = setup.encode();
    ASSERT_FALSE(enc.empty());

    auto dec = RrcSetup::decode(enc);
    EXPECT_EQ(dec.rrc_transaction_id, 1u);
    EXPECT_EQ(dec.srb_identity, 1u);
    EXPECT_EQ(dec.rlc_mode, RlcMode::AM);
    EXPECT_EQ(dec.master_cell_group, setup.master_cell_group);
}

TEST(RrcMessageTest, RrcSetupCompleteWithNasPdu) {
    RrcSetupComplete comp;
    comp.rrc_transaction_id = 1;
    comp.selected_plmn_identity = 1;
    comp.dedicated_nas_message = {0x7E, 0x00, 0x41, 0x71, 0x01, 0x02, 0x03}; // 5GMM Registration Request

    auto enc = comp.encode();
    ASSERT_FALSE(enc.empty());

    auto dec = RrcSetupComplete::decode(enc);
    EXPECT_EQ(dec.rrc_transaction_id, 1u);
    EXPECT_EQ(dec.selected_plmn_identity, 1u);
    EXPECT_EQ(dec.dedicated_nas_message, comp.dedicated_nas_message);
}

TEST(RrcMessageTest, RrcReconfigurationRoundTrip) {
    RrcReconfiguration reconf;
    reconf.rrc_transaction_id = 2;
    reconf.drb_identity = 1; // DRB1
    reconf.qfi = 1;          // QoS Flow 1
    reconf.secondary_cell_group = {0xCA, 0xFE, 0xBA, 0xBE};

    auto enc = reconf.encode();
    ASSERT_FALSE(enc.empty());

    auto dec = RrcReconfiguration::decode(enc);
    EXPECT_EQ(dec.rrc_transaction_id, 2u);
    EXPECT_EQ(dec.drb_identity, 1u);
    EXPECT_EQ(dec.qfi, 1u);
    EXPECT_EQ(dec.secondary_cell_group, reconf.secondary_cell_group);
}

TEST(RrcMessageTest, RrcReconfigurationCompleteRoundTrip) {
    RrcReconfigurationComplete comp;
    comp.rrc_transaction_id = 2;

    auto enc = comp.encode();
    ASSERT_FALSE(enc.empty());

    auto dec = RrcReconfigurationComplete::decode(enc);
    EXPECT_EQ(dec.rrc_transaction_id, 2u);
}

// ─── Integration: Full RRC 5-Step Handshake ─────────────────────────────────

TEST(RrcIntegrationTest, FullRadioHandshakeUeGnb) {
    // 1. UE sends RRCSetupRequest
    RrcSetupRequest setup_req;
    setup_req.ue_identity_type = InitialUeIdentityType::RandomValue;
    setup_req.ue_identity_val = 0x3A2B1CULL;
    setup_req.establishment_cause = EstablishmentCause::MoData;

    auto wire_req = setup_req.encode();
    auto gnb_req = RrcSetupRequest::decode(wire_req);
    EXPECT_EQ(gnb_req.establishment_cause, EstablishmentCause::MoData);

    // 2. gNodeB sends RRCSetup
    RrcSetup setup;
    setup.rrc_transaction_id = 0;
    setup.srb_identity = 1;
    setup.rlc_mode = RlcMode::AM;
    setup.master_cell_group = {0x01, 0x02, 0x03};

    auto wire_setup = setup.encode();
    auto ue_setup = RrcSetup::decode(wire_setup);
    EXPECT_EQ(ue_setup.srb_identity, 1u);

    // 3. UE sends RRCSetupComplete with initial NAS message
    RrcSetupComplete setup_comp;
    setup_comp.rrc_transaction_id = 0;
    setup_comp.selected_plmn_identity = 1;
    setup_comp.dedicated_nas_message = {0x7E, 0x00, 0x41}; // 5GS Registration

    auto wire_comp = setup_comp.encode();
    auto gnb_comp = RrcSetupComplete::decode(wire_comp);
    EXPECT_EQ(gnb_comp.selected_plmn_identity, 1u);
    EXPECT_EQ(gnb_comp.dedicated_nas_message[0], 0x7E);

    // 4. gNodeB sends RRCReconfiguration
    RrcReconfiguration reconf;
    reconf.rrc_transaction_id = 1;
    reconf.drb_identity = 1;
    reconf.qfi = 9;

    auto wire_reconf = reconf.encode();
    auto ue_reconf = RrcReconfiguration::decode(wire_reconf);
    EXPECT_EQ(ue_reconf.drb_identity, 1u);
    EXPECT_EQ(ue_reconf.qfi, 9u);

    // 5. UE sends RRCReconfigurationComplete
    RrcReconfigurationComplete reconf_comp;
    reconf_comp.rrc_transaction_id = 1;

    auto wire_reconf_comp = reconf_comp.encode();
    auto gnb_reconf_comp = RrcReconfigurationComplete::decode(wire_reconf_comp);
    EXPECT_EQ(gnb_reconf_comp.rrc_transaction_id, 1u);
}
