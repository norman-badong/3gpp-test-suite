#include <gtest/gtest.h>
#include <3gpp/emergency/StunMessage.hpp>
#include <3gpp/emergency/TurnMessage.hpp>
#include <3gpp/emergency/IceAgent.hpp>
#include <3gpp/emergency/EmergencySession.hpp>
#include <3gpp/emergency/EmergencyTypes.hpp>

using namespace gpp::emergency;

// ============================================================================
// Emergency Types Tests
// ============================================================================

TEST(EmergencyTypesTest, EmergencyServiceUrnFromCategory) {
    auto police = EmergencyServiceUrn::from_category(EmergencyCategory::Police);
    EXPECT_EQ(police.urn, "urn:service:sos.police");
    EXPECT_EQ(police.category, EmergencyCategory::Police);

    auto ambulance = EmergencyServiceUrn::from_category(EmergencyCategory::Ambulance);
    EXPECT_EQ(ambulance.urn, "urn:service:sos.ambulance");

    auto fire = EmergencyServiceUrn::from_category(EmergencyCategory::Fire);
    EXPECT_EQ(fire.urn, "urn:service:sos.fire");

    auto general = EmergencyServiceUrn::from_category(EmergencyCategory::GeneralEmergency);
    EXPECT_EQ(general.urn, "urn:service:sos");
}

TEST(EmergencyTypesTest, LocationInfo) {
    LocationInfo loc;
    EXPECT_FALSE(loc.has_location());

    loc.type = LocationType::Geodetic;
    loc.geodetic.latitude = 37.7749;
    loc.geodetic.longitude = -122.4194;
    EXPECT_TRUE(loc.has_location());
}

TEST(EmergencyTypesTest, EmergencyCallContext) {
    EmergencyCallContext ctx;
    ctx.service_urn = EmergencyServiceUrn::from_category(EmergencyCategory::Police);
    ctx.category = EmergencyCategory::Police;
    ctx.mode = EmergencySessionMode::EmergencyOnly;
    ctx.call_id = "test-call-id@127.0.0.1";

    EXPECT_EQ(ctx.category, EmergencyCategory::Police);
    EXPECT_EQ(ctx.mode, EmergencySessionMode::EmergencyOnly);
}

// ============================================================================
// STUN Message Tests
// ============================================================================

TEST(StunMessageTest, BindingRequestEncodeDecode) {
    std::array<uint8_t, 12> tid = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
    StunMessage req = StunMessage::create_binding_request(tid);

    auto encoded = req.encode_with_fingerprint();
    ASSERT_FALSE(encoded.empty());

    auto decoded = StunMessage::decode(encoded);
    ASSERT_TRUE(decoded.has_value());

    EXPECT_EQ(decoded->header.msg_type, StunMessageType::BindingRequest);
    EXPECT_EQ(decoded->header.transaction_id, tid);
    EXPECT_TRUE(decoded->verify_fingerprint());
}

TEST(StunMessageTest, BindingResponseEncodeDecode) {
    std::array<uint8_t, 12> tid = {0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C};
    StunMessage req = StunMessage::create_binding_request(tid);

    StunXorAddress mapped = StunXorAddress::from_ipv4(0xC0A80001, 50000); // 192.168.0.1:50000
    StunMessage resp = StunMessage::create_binding_response(req, mapped);

    auto encoded = resp.encode_with_fingerprint();
    ASSERT_FALSE(encoded.empty());

    auto decoded = StunMessage::decode(encoded);
    ASSERT_TRUE(decoded.has_value());

    EXPECT_EQ(decoded->header.msg_type, StunMessageType::BindingResponse);
    EXPECT_EQ(decoded->header.transaction_id, tid);
    EXPECT_TRUE(decoded->verify_fingerprint());

    auto xor_addr = decoded->get_xor_mapped_address();
    ASSERT_TRUE(xor_addr.has_value());
    EXPECT_EQ(xor_addr->port, 50000);
    EXPECT_EQ(xor_addr->addr[12], 0xC0);
    EXPECT_EQ(xor_addr->addr[13], 0xA8);
    EXPECT_EQ(xor_addr->addr[14], 0x00);
    EXPECT_EQ(xor_addr->addr[15], 0x01);
}

TEST(StunMessageTest, XorAddressIpv6) {
    std::array<uint8_t, 16> ipv6 = {0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
                                     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
    StunXorAddress addr = StunXorAddress::from_ipv6(ipv6, 3478);

    EXPECT_EQ(addr.family, StunAddressFamily::IPv6);
    EXPECT_EQ(addr.port, 3478);
    EXPECT_EQ(addr.addr, ipv6);
}

TEST(StunMessageTest, ErrorResponse) {
    std::array<uint8_t, 12> tid = {0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C};
    StunMessage req = StunMessage::create_binding_request(tid);

    StunErrorCode err = StunErrorCode::from_full(401); // Unauthorized
    err.reason = "Authentication required";
    StunMessage resp = StunMessage::create_binding_error_response(req, err);

    auto encoded = resp.encode_with_fingerprint();
    auto decoded = StunMessage::decode(encoded);
    ASSERT_TRUE(decoded.has_value());

    EXPECT_EQ(decoded->header.msg_type, StunMessageType::BindingErrorResponse);
    auto dec_err = decoded->get_error_code();
    ASSERT_TRUE(dec_err.has_value());
    EXPECT_EQ(dec_err->full_code(), 401);
    EXPECT_EQ(dec_err->reason, "Authentication required");
}

TEST(StunMessageTest, MessageIntegrity) {
    std::array<uint8_t, 12> tid = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C};
    StunMessage req = StunMessage::create_binding_request(tid);

    std::vector<uint8_t> key = {'k', 'e', 'y'};
    req.add_message_integrity(key);
    req.add_fingerprint();

    auto encoded = req.encode();
    auto decoded = StunMessage::decode(encoded);
    ASSERT_TRUE(decoded.has_value());

    EXPECT_TRUE(decoded->verify_message_integrity(key));
    EXPECT_FALSE(decoded->verify_message_integrity(std::vector<uint8_t>{'w', 'r', 'o', 'n', 'g'}));
}

TEST(StunMessageTest, SoftwareAttribute) {
    StunMessage msg = StunMessage::create_binding_request({0});
    msg.add_software("Test STUN Client 1.0");
    msg.add_fingerprint();

    auto encoded = msg.encode();
    auto decoded = StunMessage::decode(encoded);
    ASSERT_TRUE(decoded.has_value());

    auto sw = decoded->get_software();
    ASSERT_TRUE(sw.has_value());
    EXPECT_EQ(*sw, "Test STUN Client 1.0");
}

// ============================================================================
// TURN Message Tests
// ============================================================================

TEST(TurnMessageTest, ChannelDataEncodeDecode) {
    TurnChannelData ch;
    ch.channel_number = 0x4001;
    ch.length = 5;
    ch.data = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"

    auto encoded = ch.encode();
    ASSERT_FALSE(encoded.empty());

    size_t offset = 0;
    auto decoded = TurnChannelData::decode(encoded, offset);
    ASSERT_TRUE(decoded.has_value());

    EXPECT_EQ(decoded->channel_number, 0x4001);
    EXPECT_EQ(decoded->length, 5);
    EXPECT_EQ(decoded->data, ch.data);
    EXPECT_TRUE(decoded->is_channel_data());
}

TEST(TurnMessageTest, TurnClientAllocate) {
    TurnServerConfig config;
    config.hostname = "turn.example.com";
    config.realm = "turn.example.com";
    config.username = "user";
    config.password = "pass";

    TurnClient client(config);

    StunMessage alloc_req = client.create_allocate_request(600, false, StunTransportProtocol::UDP);
    EXPECT_EQ(alloc_req.header.msg_type, StunMessageType::AllocateRequest);
    EXPECT_TRUE(alloc_req.get_requested_transport().has_value());
    EXPECT_EQ(*alloc_req.get_requested_transport(), StunTransportProtocol::UDP);
    EXPECT_EQ(*alloc_req.get_lifetime(), 600);
}

TEST(TurnMessageTest, TurnClientRefresh) {
    TurnServerConfig config;
    config.username = "user";
    config.realm = "realm";
    config.password = "pass";

    TurnClient client(config);
    TurnAllocation alloc;
    alloc.username = "user";
    alloc.realm = "realm";
    alloc.nonce = "nonce";
    alloc.relayed_address = StunXorAddress::from_ipv4(0xC0A80064, 50000);

    StunMessage refresh = client.create_refresh_request(alloc, 600);
    EXPECT_EQ(refresh.header.msg_type, StunMessageType::RefreshRequest);
    EXPECT_EQ(*refresh.get_lifetime(), 600);
    EXPECT_EQ(*refresh.get_username(), "user");
}

TEST(TurnMessageTest, TurnClientPermission) {
    TurnServerConfig config;
    config.username = "user";
    config.realm = "realm";
    config.password = "pass";

    TurnClient client(config);
    TurnAllocation alloc;
    alloc.username = "user";
    alloc.realm = "realm";
    alloc.nonce = "nonce";

    StunXorAddress peer = StunXorAddress::from_ipv4(0x0A000002, 6000); // 10.0.0.2:6000
    StunMessage perm = client.create_permission_request(alloc, peer);
    EXPECT_EQ(perm.header.msg_type, StunMessageType::CreatePermissionRequest);
    EXPECT_EQ(*perm.get_username(), "user");
}

TEST(TurnMessageTest, TurnServerAllocate) {
    TurnServerConfig config;
    config.default_lifetime = 600;

    TurnServer server(config);
    TurnServer::AllocationRecord record;

    StunMessage alloc_req = StunMessage::create_binding_request({0});
    alloc_req.header.msg_type = StunMessageType::AllocateRequest;
    alloc_req.add_requested_transport(StunTransportProtocol::UDP);
    alloc_req.add_lifetime(600);
    alloc_req.add_fingerprint();

    auto resp = server.handle_request(alloc_req, StunXorAddress::from_ipv4(0x7F000001, 50000), record);
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->header.msg_type, StunMessageType::AllocateResponse);
    EXPECT_TRUE(resp->get_xor_relayed_address().has_value());
    EXPECT_TRUE(resp->get_xor_mapped_address().has_value());
    EXPECT_EQ(*resp->get_lifetime(), 600);
}

// ============================================================================
// ICE Agent Tests
// ============================================================================

TEST(IceAgentTest, CandidatePriority) {
    uint32_t host_prio = IceCandidate::compute_priority(IceCandidateType::Host, 65535, 1);
    uint32_t srflx_prio = IceCandidate::compute_priority(IceCandidateType::ServerReflexive, 65534, 1);
    uint32_t relay_prio = IceCandidate::compute_priority(IceCandidateType::Relayed, 65533, 1);

    // Host > ServerReflexive > Relayed
    EXPECT_GT(host_prio, srflx_prio);
    EXPECT_GT(srflx_prio, relay_prio);
}

TEST(IceAgentTest, CandidateSdpRoundTrip) {
    IceCandidate orig;
    orig.foundation = "1";
    orig.component_id = 1;
    orig.transport = IceTransport::UDP;
    orig.priority = 2130706431;
    orig.address = StunXorAddress::from_ipv4(0x7F000001, 5000);
    orig.type = IceCandidateType::Host;

    std::string sdp = orig.to_sdp();
    EXPECT_FALSE(sdp.empty());
    EXPECT_NE(sdp.find("a=candidate:"), std::string::npos);
    EXPECT_NE(sdp.find("typ host"), std::string::npos);

    auto parsed = IceCandidate::from_sdp(sdp);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->foundation, orig.foundation);
    EXPECT_EQ(parsed->component_id, orig.component_id);
    EXPECT_EQ(parsed->transport, orig.transport);
    EXPECT_EQ(parsed->type, orig.type);
}

TEST(IceAgentTest, CandidateSdpSrflx) {
    IceCandidate orig;
    orig.foundation = "1";
    orig.component_id = 1;
    orig.transport = IceTransport::UDP;
    orig.priority = 1853070335;
    orig.address = StunXorAddress::from_ipv4(0xC0A80001, 6000);
    orig.type = IceCandidateType::ServerReflexive;
    orig.related_address = "127.0.0.1";
    orig.related_port = 5000;

    std::string sdp = orig.to_sdp();
    EXPECT_NE(sdp.find("typ srflx"), std::string::npos);
    EXPECT_NE(sdp.find("raddr 127.0.0.1"), std::string::npos);
    EXPECT_NE(sdp.find("rport 5000"), std::string::npos);

    auto parsed = IceCandidate::from_sdp(sdp);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->type, IceCandidateType::ServerReflexive);
    EXPECT_EQ(parsed->related_address, "127.0.0.1");
    EXPECT_EQ(parsed->related_port, 5000);
}

TEST(IceAgentTest, IceCredentialsGeneration) {
    auto [ufrag, pwd] = ice_sdp::generate_credentials();
    EXPECT_GE(ufrag.size(), 4);
    EXPECT_GE(pwd.size(), 22);
}

TEST(IceAgentTest, AgentCreation) {
    IceConfig config;
    config.role = IceRole::Controlling;

    IceCallbacks callbacks;
    callbacks.on_local_candidate = [](const IceCandidate&) {};
    callbacks.on_remote_candidate = [](const IceCandidate&) {};
    callbacks.on_nominated = [](const CandidatePair&) {};
    callbacks.on_failed = [](const std::string&) {};
    callbacks.on_send_stun = [](const StunXorAddress&, const std::vector<uint8_t>&) {};

    IceAgent agent(config, std::move(callbacks));
    EXPECT_EQ(agent.state(), IceAgent::State::Gathering);
    EXPECT_FALSE(agent.local_ufrag().empty());
    EXPECT_FALSE(agent.local_pwd().empty());
}

TEST(IceAgentTest, AgentStartGathering) {
    IceConfig config;
    config.role = IceRole::Controlling;

    IceCallbacks callbacks;
    bool candidate_received = false;
    callbacks.on_local_candidate = [&](const IceCandidate&) { candidate_received = true; };
    callbacks.on_remote_candidate = [](const IceCandidate&) {};
    callbacks.on_nominated = [](const CandidatePair&) {};
    callbacks.on_failed = [](const std::string&) {};
    callbacks.on_send_stun = [](const StunXorAddress&, const std::vector<uint8_t>&) {};

    IceAgent agent(config, std::move(callbacks));
    agent.start_gathering();

    // Should have at least host candidate
    EXPECT_TRUE(candidate_received);
    EXPECT_FALSE(agent.local_candidates().empty());
}

TEST(IceAgentTest, PairPriorityComputation) {
    IceConfig config;
    config.role = IceRole::Controlling;

    IceCallbacks callbacks;
    callbacks.on_local_candidate = [](const IceCandidate&) {};
    callbacks.on_remote_candidate = [](const IceCandidate&) {};
    callbacks.on_nominated = [](const CandidatePair&) {};
    callbacks.on_failed = [](const std::string&) {};
    callbacks.on_send_stun = [](const StunXorAddress&, const std::vector<uint8_t>&) {};

    IceAgent agent(config, std::move(callbacks));

    IceCandidate local;
    local.priority = 1000;
    IceCandidate remote;
    remote.priority = 2000;

    uint64_t pair_prio = agent.compute_pair_priority(local, remote);
    // pair_priority = 2^32 * min(G,D) + 2 * max(G,D) + (G>D?1:0)
    // min=1000, max=2000, G=1000, D=2000, G>D=false
    // = 2^32 * 1000 + 2 * 2000 + 0
    EXPECT_GT(pair_prio, 0);
}

// ============================================================================
// Emergency Session Tests
// ============================================================================

TEST(EmergencySessionTest, PidfLoXmlGeneration) {
    PidfLo pidf;
    pidf.entity = "sip:user@example.com";
    pidf.id = "tuple1";
    pidf.timestamp = 1234567890;
    pidf.method = "GPS";
    pidf.confidence = 0.95f;

    pidf.location.type = LocationType::Geodetic;
    pidf.location.geodetic.latitude = 37.7749;
    pidf.location.geodetic.longitude = -122.4194;
    pidf.location.geodetic.horizontal_accuracy = 15.0;

    std::string xml = pidf.to_xml();
    EXPECT_FALSE(xml.empty());
    EXPECT_NE(xml.find("<?xml"), std::string::npos);
    EXPECT_NE(xml.find("presence"), std::string::npos);
    EXPECT_NE(xml.find("geopriv"), std::string::npos);
    EXPECT_NE(xml.find("37.7749"), std::string::npos);
    EXPECT_NE(xml.find("-122.4194"), std::string::npos);
}

TEST(EmergencySessionTest, PidfLoXmlWithCivic) {
    PidfLo pidf;
    pidf.entity = "sip:user@example.com";
    pidf.id = "tuple1";
    pidf.timestamp = 1234567890;
    pidf.method = "A-GPS";
    pidf.confidence = 0.90f;

    pidf.location.type = LocationType::CivicAddress;
    pidf.location.civic.country = "US";
    pidf.location.civic.state = "CA";
    pidf.location.civic.city = "San Francisco";
    pidf.location.civic.street = "Market St";
    pidf.location.civic.house_number = "100";

    std::string xml = pidf.to_xml();
    EXPECT_NE(xml.find("civicAddress"), std::string::npos);
    EXPECT_NE(xml.find("US"), std::string::npos);
    EXPECT_NE(xml.find("CA"), std::string::npos);
    EXPECT_NE(xml.find("San Francisco"), std::string::npos);
}

TEST(EmergencySessionTest, GeolocationHeader) {
    GeolocationHeader geo;
    geo.uri = "cid:location@call-id";
    geo.routing = "yes";
    geo.purpose = "emergency";

    std::string hdr = geo.to_header_value();
    EXPECT_NE(hdr.find("cid:location@call-id"), std::string::npos);
    EXPECT_NE(hdr.find("routing=yes"), std::string::npos);
    EXPECT_NE(hdr.find("purpose=emergency"), std::string::npos);
}

TEST(EmergencySessionTest, SipMessageEncode) {
    SipMessage msg;
    msg.method = EmergencySipMethod::Invite;
    msg.request_uri = "sip:psap@emergency.test";
    msg.add_header("Via", "SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK123");
    msg.add_header("To", "<sip:psap@emergency.test>");
    msg.add_header("From", "<sip:user@example.com>;tag=123");
    msg.add_header("Call-ID", "call-id@127.0.0.1");
    msg.add_header("CSeq", "1 INVITE");
    msg.set_body("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n", "application/sdp");

    std::string encoded = msg.encode();
    EXPECT_NE(encoded.find("INVITE sip:psap@emergency.test SIP/2.0"), std::string::npos);
    EXPECT_NE(encoded.find("Via: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK123"), std::string::npos);
    EXPECT_NE(encoded.find("Content-Type: application/sdp"), std::string::npos);
    EXPECT_NE(encoded.find("v=0"), std::string::npos);
}

TEST(EmergencySessionTest, EmergencySessionCreation) {
    EmergencySessionConfig config;
    config.imsi = "001010123456789";
    config.impi = "user@test.com";
    config.impu = "sip:user@test.com";
    config.home_domain = "test.com";
    config.pcscf_addr = "127.0.0.1";
    config.local_ip = "127.0.0.1";

    EmergencySessionCallbacks callbacks;
    callbacks.on_send_sip = [](const SipMessage&) {};
    callbacks.on_state_change = [](EmergencySessionState) {};
    callbacks.on_media_negotiation = [](const std::string&) {};
    callbacks.on_media_established = [](const std::string&) {};
    callbacks.on_location_update = [](const LocationInfo&) {};
    callbacks.on_call_ended = [](const std::string&) {};

    EmergencySession session(config, std::move(callbacks));
    EXPECT_EQ(session.state(), EmergencySessionState::Idle);
}

TEST(EmergencySessionTest, EmergencyRegistrationManager) {
    EmergencyRegistrationManager::RegistrationInfo info;
    info.impi = "user@test.com";
    info.impu = "sip:user@test.com";
    info.home_domain = "test.com";
    info.pcscf_addr = "127.0.0.1";
    info.expires = 3600;

    bool send_called = false;
    bool state_called = false;

    EmergencyRegistrationManager mgr(info,
        [&](const SipMessage&) { send_called = true; },
        [&](bool registered, const std::string&) { state_called = true; EXPECT_TRUE(registered); });

    mgr.start();
    EXPECT_TRUE(send_called);

    // Simulate 200 OK response
    SipMessage resp;
    resp.request_uri = "SIP/2.0 200 OK";
    resp.add_header("Call-ID", info.impu);
    resp.add_header("CSeq", "1 REGISTER");
    resp.add_header("Contact", "<sip:user@127.0.0.1;transport=UDP>;reg-id=1");
    resp.add_header("Expires", "3600");
    resp.add_header("Record-Route", "<sip:pcscf.test.com;lr>");

    mgr.handle_response(resp);
    EXPECT_TRUE(state_called);
    EXPECT_TRUE(mgr.is_registered());
    EXPECT_FALSE(mgr.route_set().empty());
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST(EmergencyIntegrationTest, StunTurnIceFlow) {
    // 1. STUN Binding Request/Response
    std::array<uint8_t, 12> tid = {0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC};
    StunMessage stun_req = StunMessage::create_binding_request(tid);
    StunXorAddress mapped = StunXorAddress::from_ipv4(0xC0A80001, 50000);
    StunMessage stun_resp = StunMessage::create_binding_response(stun_req, mapped);

    auto stun_resp_enc = stun_resp.encode_with_fingerprint();
    auto stun_resp_dec = StunMessage::decode(stun_resp_enc);
    ASSERT_TRUE(stun_resp_dec.has_value());
    EXPECT_EQ(stun_resp_dec->header.msg_type, StunMessageType::BindingResponse);

    // 2. TURN Allocate
    TurnServerConfig turn_cfg;
    turn_cfg.realm = "turn.test";
    turn_cfg.username = "user";
    turn_cfg.password = "pass";

    TurnClient turn_client(turn_cfg);
    TurnServer turn_server(turn_cfg);
    TurnServer::AllocationRecord record;

    StunMessage alloc_req = turn_client.create_allocate_request(600);
    auto alloc_resp = turn_server.handle_request(alloc_req, StunXorAddress::from_ipv4(0x7F000001, 50000), record);
    ASSERT_TRUE(alloc_resp.has_value());

    TurnAllocation allocation;
    EXPECT_TRUE(turn_client.handle_allocate_response(*alloc_resp, allocation));
    EXPECT_EQ(allocation.state, TurnAllocationState::Allocated);

    // 3. ICE Agent pair formation
    IceConfig ice_cfg;
    ice_cfg.role = IceRole::Controlling;

    IceCallbacks ice_cb;
    ice_cb.on_local_candidate = [](const IceCandidate&) {};
    ice_cb.on_remote_candidate = [](const IceCandidate&) {};
    ice_cb.on_nominated = [](const CandidatePair&) {};
    ice_cb.on_failed = [](const std::string&) {};
    ice_cb.on_send_stun = [](const StunXorAddress&, const std::vector<uint8_t>&) {};

    IceAgent ice_agent(ice_cfg, std::move(ice_cb));
    ice_agent.start_gathering();

    EXPECT_FALSE(ice_agent.local_candidates().empty());
}

TEST(EmergencyIntegrationTest, FullEmergencyCallFlow) {
    // This test validates the complete emergency call flow components work together
    EmergencySessionConfig config;
    config.imsi = "001010123456789";
    config.impi = "user@emergency.test";
    config.impu = "sip:+15551234567@emergency.test";
    config.home_domain = "emergency.test";
    config.pcscf_addr = "127.0.0.1";
    config.local_ip = "127.0.0.1";
    config.include_location = true;

    config.initial_location.type = LocationType::Geodetic;
    config.initial_location.geodetic.latitude = 37.7749;
    config.initial_location.geodetic.longitude = -122.4194;

    EmergencySessionCallbacks callbacks;
    bool call_started = false, call_connected = false, call_ended = false;
    callbacks.on_send_sip = [&](const SipMessage& msg) {
        if (msg.method == EmergencySipMethod::Invite) call_started = true;
        else if (msg.method == EmergencySipMethod::Ack) call_connected = true;
        else if (msg.method == EmergencySipMethod::Bye) call_ended = true;
    };
    callbacks.on_state_change = [](EmergencySessionState) {};
    callbacks.on_media_negotiation = [](const std::string&) {};
    callbacks.on_media_established = [](const std::string&) {};
    callbacks.on_location_update = [](const LocationInfo&) {};
    callbacks.on_call_ended = [](const std::string&) {};

    EmergencySession session(config, std::move(callbacks));

    // Registration
    session.start_emergency_registration();
    SipMessage reg_resp;
    reg_resp.request_uri = "SIP/2.0 200 OK";
    reg_resp.add_header("Call-ID", config.impu);
    reg_resp.add_header("CSeq", "1 REGISTER");
    reg_resp.add_header("Expires", "3600");
    reg_resp.add_header("Record-Route", "<sip:pcscf.test;lr>");
    session.handle_sip_response(reg_resp, 1);

    // Emergency call
    session.start_emergency_call(EmergencyCategory::Police);

    SipMessage invite_resp;
    invite_resp.request_uri = "SIP/2.0 183 Session Progress";
    invite_resp.add_header("Call-ID", config.impu);
    invite_resp.add_header("CSeq", "2 INVITE");
    invite_resp.add_header("Content-Type", "application/sdp");
    invite_resp.set_body("v=0\r\no=- 1 1 IN IP4 192.168.0.10\r\ns=-\r\nt=0 0\r\nm=audio 40000 RTP/AVP 97\r\na=rtpmap:97 AMR-WB/16000\r\n", "application/sdp");
    session.handle_sip_response(invite_resp, 2);

    SipMessage ok_resp;
    ok_resp.request_uri = "SIP/2.0 200 OK";
    ok_resp.add_header("Call-ID", config.impu);
    ok_resp.add_header("CSeq", "2 INVITE");
    ok_resp.add_header("Session-Expires", "1800;refresher=uac");
    session.handle_sip_response(ok_resp, 2);

    session.end_call("Normal");

    EXPECT_TRUE(call_started);
    EXPECT_TRUE(call_connected);
    EXPECT_TRUE(call_ended);
}
