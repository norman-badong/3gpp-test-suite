#include <gtest/gtest.h>
#include <thread>
#include "3gpp/common/ByteStream.hpp"
#include "3gpp/common/BitBuffer.hpp"
#include "3gpp/common/PcapWriter.hpp"
#include "3gpp/ip/IpAddress.hpp"
#include "3gpp/ip/Checksum.hpp"
#include "3gpp/ip/Ipv4Header.hpp"
#include "3gpp/ip/Ipv6Header.hpp"
#include "3gpp/ip/UdpPacket.hpp"
#include "3gpp/ip/TcpPacket.hpp"
#include "3gpp/ip/Socket.hpp"

using namespace gpp;

// =================================================================
// 1. Common Utilities Tests
// =================================================================

TEST(CommonTest, ByteStreamBigEndian) {
    common::ByteStreamWriter writer;
    writer.write_u8(0x12);
    writer.write_u16(0x3456);
    writer.write_u24(0x789ABC);
    writer.write_u32(0xDEF01234);
    writer.write_u64(0x1122334455667788ULL);

    common::ByteStreamReader reader(writer.data());
    EXPECT_EQ(reader.read_u8(), 0x12);
    EXPECT_EQ(reader.read_u16(), 0x3456);
    EXPECT_EQ(reader.read_u24(), 0x789ABC);
    EXPECT_EQ(reader.read_u32(), 0xDEF01234);
    EXPECT_EQ(reader.read_u64(), 0x1122334455667788ULL);
    EXPECT_TRUE(reader.empty());
}

TEST(CommonTest, BitBufferPackUnpack) {
    common::BitWriter bw;
    bw.write_bits(0b101, 3);      // 3 bits
    bw.write_bits(0b11001, 5);    // 5 bits -> completes byte 1: 0b10111001 = 0xB9
    bw.write_bits(0b1111, 4);     // 4 bits
    bw.pad_to_byte();             // pads 4 zero bits -> byte 2: 0xF0

    ASSERT_EQ(bw.total_bytes(), 2);
    EXPECT_EQ(bw.bytes()[0], 0xB9);
    EXPECT_EQ(bw.bytes()[1], 0xF0);

    common::BitReader br(bw.bytes());
    EXPECT_EQ(br.read_bits(3), 0b101);
    EXPECT_EQ(br.read_bits(5), 0b11001);
    EXPECT_EQ(br.read_bits(4), 0b1111);
    EXPECT_EQ(br.read_bits(4), 0b0000); // the padding bits
}

// =================================================================
// 2. IP Address & Checksum Tests
// =================================================================

TEST(IpTest, AddressParsing) {
    auto v4 = ip::Ipv4Address::from_string("192.168.1.100");
    EXPECT_EQ(v4.to_string(), "192.168.1.100");
    EXPECT_EQ(v4.bytes()[0], 192);
    EXPECT_EQ(v4.bytes()[3], 100);

    auto v6 = ip::Ipv6Address::from_string("2001:db8::1");
    EXPECT_EQ(v6.to_string(), "2001:db8::1");
}

TEST(IpTest, ChecksumRFC1071) {
    // Known RFC 1071 vector: [0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06]
    // with dummy 0 for checksum, and src 192.168.1.1, dst 192.168.1.2
    ip::Ipv4Header hdr;
    hdr.total_length = 60;
    hdr.identification = 0x1c46;
    hdr.flag_dont_fragment = true;
    hdr.ttl = 64;
    hdr.protocol = 6; // TCP
    hdr.src_ip = ip::Ipv4Address(192, 168, 1, 1);
    hdr.dst_ip = ip::Ipv4Address(192, 168, 1, 2);

    common::ByteStreamWriter writer;
    hdr.encode(writer, true);

    // Verify computed checksum is non-zero
    common::ByteStreamReader reader(writer.data());
    auto decoded = ip::Ipv4Header::decode(reader);
    EXPECT_NE(decoded.checksum, 0);

    // Recomputing checksum over entire valid header should equal 0 in one's complement sum
    uint16_t verification = ip::Checksum::compute(writer.data());
    EXPECT_EQ(verification, 0);
}

// =================================================================
// 3. IPv4 and IPv6 Headers Tests
// =================================================================

TEST(IpTest, Ipv4HeaderRoundTrip) {
    ip::Ipv4Header original;
    original.total_length = 52;
    original.identification = 42;
    original.flag_dont_fragment = true;
    original.ttl = 128;
    original.protocol = 17; // UDP
    original.src_ip = ip::Ipv4Address(10, 0, 0, 1);
    original.dst_ip = ip::Ipv4Address(10, 0, 0, 2);

    common::ByteStreamWriter writer;
    original.encode(writer, true);

    common::ByteStreamReader reader(writer.data());
    auto decoded = ip::Ipv4Header::decode(reader);

    EXPECT_EQ(decoded.version, 4);
    EXPECT_EQ(decoded.ihl, 5);
    EXPECT_EQ(decoded.total_length, 52);
    EXPECT_EQ(decoded.identification, 42);
    EXPECT_TRUE(decoded.flag_dont_fragment);
    EXPECT_EQ(decoded.ttl, 128);
    EXPECT_EQ(decoded.protocol, 17);
    EXPECT_EQ(decoded.src_ip.to_string(), "10.0.0.1");
    EXPECT_EQ(decoded.dst_ip.to_string(), "10.0.0.2");
}

TEST(IpTest, Ipv6HeaderRoundTrip) {
    ip::Ipv6Header original;
    original.traffic_class = 0x20;
    original.flow_label = 0x12345;
    original.payload_length = 64;
    original.next_header = 17; // UDP
    original.hop_limit = 64;
    original.src_ip = ip::Ipv6Address::from_string("fd00::1");
    original.dst_ip = ip::Ipv6Address::from_string("fd00::2");

    common::ByteStreamWriter writer;
    original.encode(writer);

    common::ByteStreamReader reader(writer.data());
    auto decoded = ip::Ipv6Header::decode(reader);

    EXPECT_EQ(decoded.version, 6);
    EXPECT_EQ(decoded.traffic_class, 0x20);
    EXPECT_EQ(decoded.flow_label, 0x12345);
    EXPECT_EQ(decoded.payload_length, 64);
    EXPECT_EQ(decoded.next_header, 17);
    EXPECT_EQ(decoded.hop_limit, 64);
    EXPECT_EQ(decoded.src_ip.to_string(), "fd00::1");
    EXPECT_EQ(decoded.dst_ip.to_string(), "fd00::2");
}

// =================================================================
// 4. UDP and TCP Packet Tests
// =================================================================

TEST(IpTest, UdpPacketEncodingWithChecksum) {
    ip::Ipv4Address src(192, 168, 1, 10);
    ip::Ipv4Address dst(192, 168, 1, 20);

    ip::UdpPacket pkt;
    pkt.src_port = 2152; // GTP-U port!
    pkt.dst_port = 2152;
    pkt.set_payload("Hello 3GPP GTP-U");

    common::ByteStreamWriter writer;
    pkt.encode(writer, &src, &dst);

    common::ByteStreamReader reader(writer.data());
    auto decoded = ip::UdpPacket::decode(reader);

    EXPECT_EQ(decoded.src_port, 2152);
    EXPECT_EQ(decoded.dst_port, 2152);
    EXPECT_EQ(decoded.length, 8 + 16);
    EXPECT_NE(decoded.checksum, 0);

    std::string payload_str(decoded.payload.begin(), decoded.payload.end());
    EXPECT_EQ(payload_str, "Hello 3GPP GTP-U");
}

TEST(IpTest, TcpPacketFlagsAndRoundTrip) {
    ip::Ipv4Address src(10, 1, 1, 1);
    ip::Ipv4Address dst(10, 1, 1, 2);

    ip::TcpPacket syn_ack;
    syn_ack.src_port = 80;
    syn_ack.dst_port = 45678;
    syn_ack.seq_number = 100000;
    syn_ack.ack_number = 50001;
    syn_ack.flags.syn = true;
    syn_ack.flags.ack = true;
    syn_ack.window_size = 64240;

    common::ByteStreamWriter writer;
    syn_ack.encode(writer, &src, &dst);

    common::ByteStreamReader reader(writer.data());
    auto decoded = ip::TcpPacket::decode(reader);

    EXPECT_EQ(decoded.src_port, 80);
    EXPECT_EQ(decoded.dst_port, 45678);
    EXPECT_EQ(decoded.seq_number, 100000);
    EXPECT_EQ(decoded.ack_number, 50001);
    EXPECT_TRUE(decoded.flags.syn);
    EXPECT_TRUE(decoded.flags.ack);
    EXPECT_FALSE(decoded.flags.fin);
    EXPECT_NE(decoded.checksum, 0);
}

// =================================================================
// 5. Socket Loopback End-to-End Tests
// =================================================================

TEST(SocketTest, UdpLoopbackEcho) {
    ip::UdpSocket server;
    ASSERT_TRUE(server.bind("127.0.0.1", 0));
    uint16_t port = server.local_port();
    ASSERT_GT(port, 0);

    ip::UdpSocket client;
    std::string test_msg = "Ping 3GPP IP Layer";
    ssize_t sent = client.send_to(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(test_msg.data()), test_msg.size()),
                                  "127.0.0.1", port);
    EXPECT_EQ(sent, static_cast<ssize_t>(test_msg.size()));

    std::array<uint8_t, 256> buf{};
    std::string from_host;
    uint16_t from_port = 0;
    ssize_t recvd = server.recv_from(buf, from_host, from_port, 1000);
    ASSERT_GT(recvd, 0);

    std::string recvd_msg(reinterpret_cast<char*>(buf.data()), recvd);
    EXPECT_EQ(recvd_msg, test_msg);
    EXPECT_EQ(from_host, "127.0.0.1");
}

TEST(SocketTest, TcpLoopbackTransfer) {
    ip::TcpListener listener;
    ASSERT_TRUE(listener.listen("127.0.0.1", 0));
    uint16_t port = listener.local_port();
    ASSERT_GT(port, 0);

    std::thread server_thread([&]() {
        ip::TcpSocket client_conn;
        std::string host;
        uint16_t cport = 0;
        if (listener.accept(client_conn, host, cport, 2000)) {
            std::array<uint8_t, 256> buf{};
            ssize_t n = client_conn.recv(buf, 2000);
            if (n > 0) {
                // Echo back
                client_conn.send(std::span<const uint8_t>(buf.data(), n));
            }
        }
    });

    ip::TcpSocket client;
    ASSERT_TRUE(client.connect("127.0.0.1", port, 2000));
    std::string msg = "3GPP SBA HTTP2 TCP Channel";
    client.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()));

    std::array<uint8_t, 256> reply_buf{};
    ssize_t n = client.recv(reply_buf, 2000);
    ASSERT_EQ(n, static_cast<ssize_t>(msg.size()));

    std::string reply(reinterpret_cast<char*>(reply_buf.data()), n);
    EXPECT_EQ(reply, msg);

    server_thread.join();
}
