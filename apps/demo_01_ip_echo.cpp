#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include "3gpp/common/Logger.hpp"
#include "3gpp/common/PcapWriter.hpp"
#include "3gpp/ip/IpAddress.hpp"
#include "3gpp/ip/Ipv4Header.hpp"
#include "3gpp/ip/Ipv6Header.hpp"
#include "3gpp/ip/UdpPacket.hpp"
#include "3gpp/ip/TcpPacket.hpp"
#include "3gpp/ip/Socket.hpp"

using namespace gpp;

void run_udp_echo_test(common::PcapWriter& pcap) {
    GPP_LOG_INFO("IP_DEMO", "=== Starting IPv4 & IPv6 UDP Echo Test ===");

    ip::UdpSocket server_sock;
    if (!server_sock.bind("127.0.0.1", 0)) {
        GPP_LOG_ERROR("IP_DEMO", "Failed to bind UDP server on 127.0.0.1");
        return;
    }
    uint16_t server_port = server_sock.local_port();
    GPP_LOG_INFO("IP_DEMO", "UDP Server listening on 127.0.0.1:" + std::to_string(server_port));

    std::thread server_thread([&]() {
        std::array<uint8_t, 1024> recv_buf{};
        std::string client_host;
        uint16_t client_port = 0;

        ssize_t n = server_sock.recv_from(recv_buf, client_host, client_port, 2000);
        if (n > 0) {
            std::string msg(reinterpret_cast<char*>(recv_buf.data()), n);
            GPP_LOG_INFO("UDP_SERVER", "Received " + std::to_string(n) + " bytes from " +
                                       client_host + ":" + std::to_string(client_port) + " -> '" + msg + "'");

            // Echo back
            std::string echo_reply = "ECHO: " + msg;
            server_sock.send_to(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(echo_reply.data()), echo_reply.size()),
                                client_host, client_port);
        }
    });

    // Client action
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    ip::UdpSocket client_sock;
    std::string test_payload = "3GPP GTP-U User-Plane Bearer Payload #101";

    GPP_LOG_INFO("UDP_CLIENT", "Sending payload to server: " + test_payload);
    client_sock.send_to(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(test_payload.data()), test_payload.size()),
                        "127.0.0.1", server_port);

    // Capture synthetic IPv4+UDP packet to PCAP
    {
        ip::Ipv4Header ip_hdr;
        ip_hdr.src_ip = ip::Ipv4Address(127, 0, 0, 1);
        ip_hdr.dst_ip = ip::Ipv4Address(127, 0, 0, 1);
        ip_hdr.protocol = 17; // UDP

        ip::UdpPacket udp_pkt;
        udp_pkt.src_port = client_sock.local_port();
        udp_pkt.dst_port = server_port;
        udp_pkt.set_payload(test_payload);

        common::ByteStreamWriter writer;
        ip_hdr.total_length = static_cast<uint16_t>(20 + udp_pkt.length);
        ip_hdr.encode(writer);
        udp_pkt.encode(writer, &ip_hdr.src_ip, &ip_hdr.dst_ip);

        pcap.write_ipv4(writer.data());
        GPP_HEXDUMP("PCAP", "Exported IPv4+UDP Packet to PCAP", writer.data());
    }

    // Client receive echo
    std::array<uint8_t, 1024> client_buf{};
    std::string reply_host;
    uint16_t reply_port = 0;
    ssize_t n = client_sock.recv_from(client_buf, reply_host, reply_port, 2000);
    if (n > 0) {
        std::string reply(reinterpret_cast<char*>(client_buf.data()), n);
        GPP_LOG_INFO("UDP_CLIENT", "Received Echo Response: '" + reply + "'");
    }

    server_thread.join();
}

void run_tcp_echo_test(common::PcapWriter& pcap) {
    GPP_LOG_INFO("IP_DEMO", "=== Starting IPv4 TCP 3-Way Handshake & Echo Test ===");

    ip::TcpListener listener;
    if (!listener.listen("127.0.0.1", 0)) {
        GPP_LOG_ERROR("IP_DEMO", "Failed to listen TCP on 127.0.0.1");
        return;
    }
    uint16_t server_port = listener.local_port();
    GPP_LOG_INFO("IP_DEMO", "TCP Server listening on 127.0.0.1:" + std::to_string(server_port));

    std::thread server_thread([&]() {
        ip::TcpSocket client_conn;
        std::string chost;
        uint16_t cport = 0;
        if (listener.accept(client_conn, chost, cport, 2000)) {
            GPP_LOG_INFO("TCP_SERVER", "Accepted connection from " + chost + ":" + std::to_string(cport));

            std::array<uint8_t, 1024> buf{};
            ssize_t n = client_conn.recv(buf, 2000);
            if (n > 0) {
                std::string msg(reinterpret_cast<char*>(buf.data()), n);
                GPP_LOG_INFO("TCP_SERVER", "Received: '" + msg + "'");
                std::string ack_msg = "ACK: " + msg;
                client_conn.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(ack_msg.data()), ack_msg.size()));
            }
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    ip::TcpSocket client;
    if (client.connect("127.0.0.1", server_port, 2000)) {
        GPP_LOG_INFO("TCP_CLIENT", "Connected to TCP server on port " + std::to_string(server_port));

        std::string payload = "3GPP 5G SBA SBI HTTP/2 Transport Init";
        client.send(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(payload.data()), payload.size()));

        // Synthetic TCP SYN packet to PCAP
        {
            ip::Ipv4Header ip_hdr;
            ip_hdr.src_ip = ip::Ipv4Address(127, 0, 0, 1);
            ip_hdr.dst_ip = ip::Ipv4Address(127, 0, 0, 1);
            ip_hdr.protocol = 6; // TCP

            ip::TcpPacket syn_pkt;
            syn_pkt.src_port = 54321;
            syn_pkt.dst_port = server_port;
            syn_pkt.seq_number = 1000;
            syn_pkt.flags.syn = true;

            common::ByteStreamWriter writer;
            ip_hdr.total_length = 40;
            ip_hdr.encode(writer);
            syn_pkt.encode(writer, &ip_hdr.src_ip, &ip_hdr.dst_ip);
            pcap.write_ipv4(writer.data());
        }

        std::array<uint8_t, 1024> recv_buf{};
        ssize_t n = client.recv(recv_buf, 2000);
        if (n > 0) {
            std::string rep(reinterpret_cast<char*>(recv_buf.data()), n);
            GPP_LOG_INFO("TCP_CLIENT", "Received TCP Echo Reply: '" + rep + "'");
        }
    }

    server_thread.join();
}

int main() {
    common::Logger::instance().set_level(common::LogLevel::DEBUG);
    GPP_LOG_INFO("MAIN", "=======================================================");
    GPP_LOG_INFO("MAIN", " 3GPP Test Suite - Lesson 1: IP Networking Test Runner ");
    GPP_LOG_INFO("MAIN", "=======================================================");

    common::PcapWriter pcap("output_01_ip_echo.pcap");
    GPP_LOG_INFO("MAIN", "Writing captured packets to 'output_01_ip_echo.pcap'...");

    run_udp_echo_test(pcap);
    run_tcp_echo_test(pcap);

    pcap.close();
    GPP_LOG_INFO("MAIN", "Finished! Captured " + std::to_string(pcap.packet_count()) + " packets into output_01_ip_echo.pcap");
    GPP_LOG_INFO("MAIN", "You can open output_01_ip_echo.pcap in Wireshark to verify packet headers!");
    return 0;
}
