#include <gtest/gtest.h>
#include "3gpp/sdp/Sdp.hpp"
#include "3gpp/sdp/SdpNegotiator.hpp"

using namespace gpp::sdp;

// =================================================================
// 1. SDP Parsing & Serialization Tests (RFC 4566)
// =================================================================

TEST(SdpTest, RtpMapAndFmtpParsing) {
    auto rtp = RtpMap::parse("104 AMR-WB/16000/1");
    EXPECT_EQ(rtp.payload_type, 104);
    EXPECT_EQ(rtp.encoding_name, "AMR-WB");
    EXPECT_EQ(rtp.clock_rate, 16000);
    EXPECT_EQ(rtp.channels, 1);
    EXPECT_EQ(rtp.to_string(), "a=rtpmap:104 AMR-WB/16000\r\n");

    auto fmtp = Fmtp::parse("104 octet-align=1; mode-change-capability=2");
    EXPECT_EQ(fmtp.payload_type, 104);
    EXPECT_EQ(fmtp.parameters, "octet-align=1; mode-change-capability=2");
    EXPECT_EQ(fmtp.to_string(), "a=fmtp:104 octet-align=1; mode-change-capability=2\r\n");
}

TEST(SdpTest, VoLteOfferGeneration) {
    auto offer = SessionDescription::make_volte_amrwb_offer("10.1.2.3", 49170);
    EXPECT_EQ(offer.version, 0);
    EXPECT_EQ(offer.session_name, "3GPP VoLTE Call");
    ASSERT_TRUE(offer.connection.has_value());
    EXPECT_EQ(offer.connection->address, "10.1.2.3");
    EXPECT_EQ(offer.connection->addr_type, "IP4");

    ASSERT_EQ(offer.media.size(), 1);
    const auto& audio = offer.media[0];
    EXPECT_EQ(audio.media_type, "audio");
    EXPECT_EQ(audio.port, 49170);
    EXPECT_EQ(audio.protocol, "RTP/AVP");
    EXPECT_EQ(audio.direction, MediaDirection::SENDRECV);

    // Verify 3GPP codecs are present
    const auto* amrwb = audio.find_rtpmap(104);
    ASSERT_NE(amrwb, nullptr);
    EXPECT_EQ(amrwb->encoding_name, "AMR-WB");
    EXPECT_EQ(amrwb->clock_rate, 16000);

    const auto* fmtp104 = audio.find_fmtp(104);
    ASSERT_NE(fmtp104, nullptr);
    EXPECT_NE(fmtp104->parameters.find("octet-align=1"), std::string::npos);
}

TEST(SdpTest, ParseAndSerializeRoundTrip) {
    std::string sample_sdp =
        "v=0\r\n"
        "o=- 123456 1 IN IP4 192.168.0.1\r\n"
        "s=3GPP IMS VoNR Call\r\n"
        "c=IN IP4 192.168.0.1\r\n"
        "t=0 0\r\n"
        "m=audio 50000 RTP/AVP 108 100\r\n"
        "a=rtpmap:108 EVS/16000\r\n"
        "a=fmtp:108 br=13.2-24.4\r\n"
        "a=rtpmap:100 telephone-event/16000\r\n"
        "a=fmtp:100 0-15\r\n"
        "a=ptime:20\r\n"
        "a=maxptime:240\r\n"
        "a=sendrecv\r\n";

    auto parsed = SessionDescription::parse(sample_sdp);
    EXPECT_EQ(parsed.version, 0);
    EXPECT_EQ(parsed.origin.session_id, 123456);
    EXPECT_EQ(parsed.session_name, "3GPP IMS VoNR Call");
    ASSERT_TRUE(parsed.connection.has_value());
    EXPECT_EQ(parsed.connection->address, "192.168.0.1");

    ASSERT_EQ(parsed.media.size(), 1);
    EXPECT_EQ(parsed.media[0].port, 50000);
    EXPECT_EQ(parsed.media[0].ptime, 20);
    EXPECT_EQ(parsed.media[0].maxptime, 240);
    EXPECT_EQ(parsed.media[0].direction, MediaDirection::SENDRECV);

    std::string reserialized = parsed.serialize();
    EXPECT_EQ(reserialized, sample_sdp);
}

// =================================================================
// 2. Offer/Answer Negotiation Tests (RFC 3264)
// =================================================================

TEST(SdpNegotiationTest, MatchedCodecSelection) {
    // Caller offers VoNR EVS (PT 108) + AMR-WB (PT 104) + DTMF (PT 100)
    auto offer = SessionDescription::make_vonr_evs_offer("10.0.0.1", 49170);

    // Callee only supports AMR-WB
    NegotiatorConfig callee_config{
        .local_address = "10.0.0.2",
        .is_ipv6 = false,
        .local_rtp_port = 52000,
        .local_direction = MediaDirection::SENDRECV,
        .preferred_codecs = {
            { "AMR-WB", 16000, "octet-align=1" }
        }
    };

    auto answer = SdpNegotiator::create_answer(offer, callee_config);

    ASSERT_EQ(answer.media.size(), 1);
    const auto& ans_audio = answer.media[0];

    // Port should be active
    EXPECT_EQ(ans_audio.port, 52000);
    EXPECT_EQ(ans_audio.direction, MediaDirection::SENDRECV);

    // Should have selected PT 104 (AMR-WB) and PT 100 (telephone-event), but NOT PT 108 (EVS)
    ASSERT_EQ(ans_audio.payload_types.size(), 2);
    EXPECT_EQ(ans_audio.payload_types[0], 104);
    EXPECT_EQ(ans_audio.payload_types[1], 100);

    const auto* rtp104 = ans_audio.find_rtpmap(104);
    ASSERT_NE(rtp104, nullptr);
    EXPECT_EQ(rtp104->encoding_name, "AMR-WB");
}

TEST(SdpNegotiationTest, IncompatibleCodecRejection) {
    auto offer = SessionDescription::make_vonr_evs_offer("10.0.0.1", 49170);

    // Callee only supports PCMU (G.711u)
    NegotiatorConfig callee_config{
        .local_address = "10.0.0.2",
        .is_ipv6 = false,
        .local_rtp_port = 52000,
        .local_direction = MediaDirection::SENDRECV,
        .preferred_codecs = {
            { "PCMU", 8000, "" }
        }
    };

    auto answer = SdpNegotiator::create_answer(offer, callee_config);
    ASSERT_EQ(answer.media.size(), 1);

    // RFC 3264 Section 6: If no stream can be supported, port is set to 0
    EXPECT_EQ(answer.media[0].port, 0);
}

TEST(SdpNegotiationTest, DirectionNegotiation) {
    auto offer = SessionDescription::make_volte_amrwb_offer("10.0.0.1", 49170);
    offer.media[0].direction = MediaDirection::SENDONLY; // Caller puts call on hold / music on hold

    NegotiatorConfig callee_config{
        .local_address = "10.0.0.2",
        .local_rtp_port = 52000,
        .local_direction = MediaDirection::SENDRECV,
        .preferred_codecs = { { "AMR-WB", 16000, "" } }
    };

    auto answer = SdpNegotiator::create_answer(offer, callee_config);
    ASSERT_EQ(answer.media.size(), 1);

    // RFC 3264 Section 6.1: If offer is sendonly, answer MUST be recvonly
    EXPECT_EQ(answer.media[0].direction, MediaDirection::RECVONLY);
}
