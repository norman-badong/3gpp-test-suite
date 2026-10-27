#include <gtest/gtest.h>
#include "3gpp/sip/SipUri.hpp"
#include "3gpp/sip/SipHeader.hpp"
#include "3gpp/sip/SipMessage.hpp"
#include "3gpp/sip/SipDialog.hpp"
#include "3gpp/sdp/Sdp.hpp"

using namespace gpp::sip;

// =================================================================
// 1. SIP URI and Header Tests (RFC 3261)
// =================================================================

TEST(SipTest, UriParsingAndFormatting) {
    auto uri = SipUri::parse("sip:alice@ims.mnc001.mcc001.3gppnetwork.org:5060;transport=udp;user=phone");
    EXPECT_EQ(uri.scheme(), "sip");
    EXPECT_EQ(uri.user(), "alice");
    EXPECT_EQ(uri.host(), "ims.mnc001.mcc001.3gppnetwork.org");
    EXPECT_EQ(uri.port(), 5060);
    EXPECT_EQ(uri.get_parameter("transport"), "udp");
    EXPECT_EQ(uri.get_parameter("user"), "phone");
    EXPECT_EQ(uri.to_string(), "sip:alice@ims.mnc001.mcc001.3gppnetwork.org;transport=udp;user=phone");
}

TEST(SipTest, ViaHeaderRoundTrip) {
    auto via = ViaHeader::parse("SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK-776asdh9;rport");
    EXPECT_EQ(via.protocol, "SIP/2.0/UDP");
    EXPECT_EQ(via.sent_by_host, "192.168.1.10");
    EXPECT_EQ(via.sent_by_port, 5060);
    EXPECT_EQ(via.branch, "z9hG4bK-776asdh9");
    EXPECT_GE(via.rport, 0);
    EXPECT_EQ(via.to_string(), "SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK-776asdh9;rport");
}

TEST(SipTest, NameAddrHeaderParsing) {
    auto hdr = NameAddrHeader::parse("\"Alice in VoLTE\" <sip:alice@ims.3gpp.local:5060>;tag=abc123xyz");
    EXPECT_EQ(hdr.display_name, "Alice in VoLTE");
    EXPECT_EQ(hdr.uri.user(), "alice");
    EXPECT_EQ(hdr.uri.host(), "ims.3gpp.local");
    EXPECT_EQ(hdr.tag, "abc123xyz");

    auto contact = NameAddrHeader::parse("<sip:alice@10.0.0.1:5060>;expires=3600");
    EXPECT_EQ(contact.uri.user(), "alice");
    EXPECT_EQ(contact.uri.host(), "10.0.0.1");
    EXPECT_EQ(contact.expires, 3600);
}

TEST(SipTest, CSeqHeaderRoundTrip) {
    auto cseq = CSeqHeader::parse("102 INVITE");
    EXPECT_EQ(cseq.seq, 102);
    EXPECT_EQ(cseq.method, "INVITE");
    EXPECT_EQ(cseq.to_string(), "102 INVITE");
}

// =================================================================
// 2. SIP Message Parsing, Building, and Case-Insensitivity
// =================================================================

TEST(SipTest, CaseInsensitiveAndCompactHeaders) {
    std::string raw_sip =
        "INVITE sip:bob@biloxi.com SIP/2.0\r\n"
        "v: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8\r\n"
        "Max-Forwards: 70\r\n"
        "t: Bob <sip:bob@biloxi.com>\r\n"
        "f: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n"
        "i: a84b4c76e66710\r\n"
        "CSeq: 314159 INVITE\r\n"
        "m: <sip:alice@pc33.atlanta.com>\r\n"
        "c: application/sdp\r\n"
        "l: 0\r\n\r\n";

    auto msg = SipMessage::parse(raw_sip);
    EXPECT_TRUE(msg.is_request());
    EXPECT_EQ(msg.method(), "INVITE");
    EXPECT_EQ(msg.request_uri().user(), "bob");

    // Case-insensitive lookup
    EXPECT_EQ(msg.call_id(), "a84b4c76e66710");
    EXPECT_EQ(msg.get_header("CALL-ID"), "a84b4c76e66710");
    EXPECT_EQ(msg.get_header("i"), "a84b4c76e66710");

    EXPECT_EQ(msg.from().tag, "1928301774");
    EXPECT_EQ(msg.to().uri.user(), "bob");
    EXPECT_EQ(msg.cseq().seq, 314159);
    EXPECT_EQ(msg.cseq().method, "INVITE");
    EXPECT_EQ(msg.contacts().size(), 1);
    EXPECT_EQ(msg.vias().size(), 1);
}

TEST(SipTest, MakeRegisterMessage) {
    SipUri registrar("", "ims.mnc001.mcc001.3gppnetwork.org");
    NameAddrHeader alice(SipUri("alice", "ims.mnc001.mcc001.3gppnetwork.org"), "Alice", "tag-alice-reg");
    NameAddrHeader contact(SipUri("alice", "10.0.0.5", 5060));

    auto reg = SipMessage::make_register(registrar, alice, alice, contact, 1, "callid-reg-01", 3600);
    EXPECT_EQ(reg.method(), "REGISTER");
    EXPECT_EQ(reg.request_uri().host(), "ims.mnc001.mcc001.3gppnetwork.org");
    EXPECT_EQ(reg.cseq().method, "REGISTER");
    EXPECT_EQ(reg.cseq().seq, 1);
    EXPECT_EQ(reg.get_header("Expires"), "3600");

    std::string serialized = reg.serialize();
    auto parsed = SipMessage::parse(serialized);
    EXPECT_EQ(parsed.method(), "REGISTER");
    EXPECT_EQ(parsed.call_id(), "callid-reg-01");
}

TEST(SipTest, MakeInviteWithEmbeddedSdp) {
    SipUri bob_uri("bob", "ims.mnc001.mcc001.3gppnetwork.org");
    NameAddrHeader alice(SipUri("alice", "ims.mnc001.mcc001.3gppnetwork.org"), "Alice", "tag-alice-123");
    NameAddrHeader bob(bob_uri, "Bob");
    NameAddrHeader contact(SipUri("alice", "10.0.0.1", 5060));

    auto sdp_offer = gpp::sdp::SessionDescription::make_volte_amrwb_offer("10.0.0.1", 49170);
    auto invite = SipMessage::make_invite(bob_uri, alice, bob, contact, 10, "callid-inv-01", sdp_offer);

    EXPECT_EQ(invite.method(), "INVITE");
    EXPECT_EQ(invite.get_header("Content-Type"), "application/sdp");
    EXPECT_GT(std::stoul(invite.get_header("Content-Length")), 0);

    // Extract embedded SDP
    auto extracted_sdp = invite.get_sdp();
    ASSERT_TRUE(extracted_sdp.has_value());
    EXPECT_EQ(extracted_sdp->media.size(), 1);
    EXPECT_EQ(extracted_sdp->media[0].port, 49170);
    EXPECT_NE(extracted_sdp->media[0].find_rtpmap(104), nullptr);
}

// =================================================================
// 3. SIP Dialog State Machine Tests (RFC 3261)
// =================================================================

TEST(SipDialogTest, CallFlowTransitions) {
    SipUri bob_uri("bob", "ims.3gpp.local");
    NameAddrHeader alice(SipUri("alice", "ims.3gpp.local"), "Alice", "tag-alice");
    NameAddrHeader bob(bob_uri, "Bob");
    NameAddrHeader contact(SipUri("alice", "10.0.0.1", 5060));

    auto sdp = gpp::sdp::SessionDescription::make_volte_amrwb_offer("10.0.0.1", 40000);
    auto invite = SipMessage::make_invite(bob_uri, alice, bob, contact, 1, "dialog-test-01", sdp);

    SipDialog dialog;
    dialog.init_as_uac(invite);
    EXPECT_EQ(dialog.state(), DialogState::IDLE);

    // 1. Receive 180 Ringing with remote tag -> EARLY
    auto ringing = SipMessage::make_response(invite, 180, "Ringing", "tag-bob-ringing");
    dialog.handle_response(ringing);
    EXPECT_EQ(dialog.state(), DialogState::EARLY);
    EXPECT_EQ(dialog.remote_tag(), "tag-bob-ringing");

    // 2. Receive 200 OK -> CONFIRMED
    auto ok_resp = SipMessage::make_response(invite, 200, "OK", "tag-bob-ringing");
    ok_resp.add_contact(NameAddrHeader(SipUri("bob", "10.0.0.2", 5060)));
    dialog.handle_response(ok_resp);
    EXPECT_EQ(dialog.state(), DialogState::CONFIRMED);
    EXPECT_EQ(dialog.remote_target().host(), "10.0.0.2");

    // 3. Generate ACK
    auto ack = dialog.make_ack();
    EXPECT_EQ(ack.method(), "ACK");
    EXPECT_EQ(ack.request_uri().host(), "10.0.0.2");
    EXPECT_EQ(ack.cseq().seq, 1);

    // 4. Terminate with BYE -> TERMINATED
    auto bye = dialog.make_bye();
    EXPECT_EQ(bye.method(), "BYE");
    EXPECT_EQ(bye.cseq().seq, 2);
    EXPECT_EQ(dialog.state(), DialogState::TERMINATED);
}
