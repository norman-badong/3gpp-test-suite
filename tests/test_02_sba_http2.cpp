#include <gtest/gtest.h>
#include <thread>
#include "3gpp/sba/Http2Frame.hpp"
#include "3gpp/sba/Hpack.hpp"
#include "3gpp/sba/TlsSocket.hpp"
#include "3gpp/sba/SbaSession.hpp"
#include "3gpp/ip/Socket.hpp"

using namespace gpp::sba;

// =================================================================
// 1. HTTP/2 Framing Tests (RFC 7540)
// =================================================================

TEST(Http2Test, FrameHeaderRoundTrip) {
    Http2FrameHeader original;
    original.length = 0x001234;
    original.type = FrameType::HEADERS;
    original.flags = FrameFlags::END_STREAM | FrameFlags::END_HEADERS;
    original.stream_id = 7;

    gpp::common::ByteStreamWriter writer;
    original.encode(writer);

    EXPECT_EQ(writer.size(), 9);

    gpp::common::ByteStreamReader reader(writer.data());
    auto decoded = Http2FrameHeader::decode(reader);

    EXPECT_EQ(decoded.length, 0x001234);
    EXPECT_EQ(decoded.type, FrameType::HEADERS);
    EXPECT_EQ(decoded.flags, FrameFlags::END_STREAM | FrameFlags::END_HEADERS);
    EXPECT_EQ(decoded.stream_id, 7);
}

TEST(Http2Test, SettingsFrameFactory) {
    std::vector<std::pair<SettingId, uint32_t>> settings = {
        { SettingId::HEADER_TABLE_SIZE, 4096 },
        { SettingId::MAX_CONCURRENT_STREAMS, 100 }
    };
    auto frame = Http2Frame::make_settings(settings);

    EXPECT_EQ(frame.header.type, FrameType::SETTINGS);
    EXPECT_EQ(frame.header.stream_id, 0);
    EXPECT_EQ(frame.header.length, 12); // 2 settings * 6 bytes each

    gpp::common::ByteStreamWriter writer;
    frame.encode(writer);

    gpp::common::ByteStreamReader reader(writer.data());
    auto decoded = Http2Frame::decode(reader);

    EXPECT_EQ(decoded.header.type, FrameType::SETTINGS);
    EXPECT_EQ(decoded.payload.size(), 12);

    auto ack_frame = Http2Frame::make_settings_ack();
    EXPECT_EQ(ack_frame.header.flags, FrameFlags::ACK);
    EXPECT_EQ(ack_frame.header.length, 0);
}

TEST(Http2Test, PingAndGoawayFrames) {
    auto ping = Http2Frame::make_ping(0x0102030405060708ULL, false);
    EXPECT_EQ(ping.header.type, FrameType::PING);
    EXPECT_EQ(ping.header.length, 8);

    auto goaway = Http2Frame::make_goaway(3, Http2ErrorCode::NO_ERROR, "Graceful Shutdown");
    EXPECT_EQ(goaway.header.type, FrameType::GOAWAY);
    EXPECT_GE(goaway.header.length, 8);
}

// =================================================================
// 2. HPACK Header Compression Tests (RFC 7541)
// =================================================================

TEST(HpackTest, IntegerVariablePrefix) {
    // 5-bit prefix test for value 10 (< 31)
    gpp::common::ByteStreamWriter w1;
    Hpack::encode_integer(w1, 0x00, 5, 10);
    EXPECT_EQ(w1.data().size(), 1);
    EXPECT_EQ(w1.data()[0], 10);

    gpp::common::ByteStreamReader r1(w1.data());
    uint8_t fb1 = r1.read_u8();
    EXPECT_EQ(Hpack::decode_integer(r1, 5, fb1), 10);

    // 5-bit prefix test for value 1337 (> 31)
    gpp::common::ByteStreamWriter w2;
    Hpack::encode_integer(w2, 0x00, 5, 1337);
    gpp::common::ByteStreamReader r2(w2.data());
    uint8_t fb2 = r2.read_u8();
    EXPECT_EQ(Hpack::decode_integer(r2, 5, fb2), 1337);
}

TEST(HpackTest, HeadersEncodeDecodeRoundTrip) {
    std::vector<HeaderField> original = {
        { ":method", "POST" },
        { ":scheme", "https" },
        { ":path", "/nnrf-nfm/v1/nf-instances" },
        { ":authority", "nrf.5gc.3gpp.local" },
        { "content-type", "application/json" },
        { "x-3gpp-sbi-sender", "amf-instance-01" }
    };

    auto block = Hpack::encode(original);
    EXPECT_FALSE(block.empty());

    auto decoded = Hpack::decode(block);
    ASSERT_EQ(decoded.size(), original.size());

    for (size_t i = 0; i < original.size(); ++i) {
        EXPECT_EQ(decoded[i].name, original[i].name);
        EXPECT_EQ(decoded[i].value, original[i].value);
    }
}

// =================================================================
// 3. End-to-End TLS 1.3 & HTTP/2 5G SBA Communication
// =================================================================

TEST(SbaTest, Tls13AlpnHandshakeAndEcho) {
    TlsContext server_ctx(TlsContext::Role::SERVER);
    ASSERT_TRUE(server_ctx.generate_self_signed_cert("5gc.local"));
    ASSERT_TRUE(server_ctx.set_alpn_protocols({"h2"}));

    gpp::ip::TcpListener listener;
    ASSERT_TRUE(listener.listen("127.0.0.1", 0));
    uint16_t port = listener.local_port();

    std::thread server_thread([&]() {
        gpp::ip::TcpSocket raw_conn;
        std::string host;
        uint16_t p = 0;
        if (listener.accept(raw_conn, host, p, 2000)) {
            TlsSocket srv_tls(server_ctx);
            if (srv_tls.accept(std::move(raw_conn))) {
                EXPECT_EQ(srv_tls.negotiated_alpn(), "h2");
                EXPECT_EQ(srv_tls.tls_version(), "TLSv1.3");

                SbaSession session(srv_tls, false);
                if (session.perform_handshake(2000)) {
                    auto req = session.receive_request(2000);
                    if (req) {
                        SbaResponse resp;
                        resp.status = 200;
                        resp.body = "{\"status\": \"OK\"}";
                        session.send_response(req->first, resp);
                    }
                }
            }
        }
    });

    TlsContext client_ctx(TlsContext::Role::CLIENT);
    ASSERT_TRUE(client_ctx.set_alpn_protocols({"h2"}));

    TlsSocket client_tls(client_ctx);
    ASSERT_TRUE(client_tls.connect("127.0.0.1", port, 2000));
    EXPECT_EQ(client_tls.negotiated_alpn(), "h2");
    EXPECT_EQ(client_tls.tls_version(), "TLSv1.3");

    SbaSession client_session(client_tls, true);
    ASSERT_TRUE(client_session.perform_handshake(2000));

    SbaRequest req;
    req.method = "GET";
    req.path = "/nnrf-disc/v1/nf-instances?nf-type=SMF";
    ASSERT_TRUE(client_session.send_request(1, req));

    auto resp = client_session.receive_response(2000);
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->status, 200);
    EXPECT_EQ(resp->body, "{\"status\": \"OK\"}");

    server_thread.join();
}
