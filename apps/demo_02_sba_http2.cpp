#include <iostream>
#include <thread>
#include <chrono>
#include "3gpp/common/Logger.hpp"
#include "3gpp/common/PcapWriter.hpp"
#include "3gpp/ip/Ipv4Header.hpp"
#include "3gpp/ip/TcpPacket.hpp"
#include "3gpp/ip/Socket.hpp"
#include "3gpp/sba/Http2Frame.hpp"
#include "3gpp/sba/Hpack.hpp"
#include "3gpp/sba/TlsSocket.hpp"
#include "3gpp/sba/SbaSession.hpp"

using namespace gpp;

void dump_frame_to_pcap(common::PcapWriter& pcap, uint16_t src_port, uint16_t dst_port, const sba::Http2Frame& frame) {
    ip::Ipv4Header ip_hdr;
    ip_hdr.src_ip = ip::Ipv4Address(127, 0, 0, 1);
    ip_hdr.dst_ip = ip::Ipv4Address(127, 0, 0, 1);
    ip_hdr.protocol = 6; // TCP

    common::ByteStreamWriter h2_bytes;
    frame.encode(h2_bytes);

    ip::TcpPacket tcp;
    tcp.src_port = src_port;
    tcp.dst_port = dst_port;
    tcp.seq_number = 1000;
    tcp.flags.psh = true;
    tcp.flags.ack = true;
    tcp.set_payload(h2_bytes.data());

    common::ByteStreamWriter writer;
    ip_hdr.total_length = static_cast<uint16_t>(20 + 20 + h2_bytes.size());
    ip_hdr.encode(writer);
    tcp.encode(writer, &ip_hdr.src_ip, &ip_hdr.dst_ip);
    pcap.write_ipv4(writer.data());
}

int main() {
    common::Logger::instance().set_level(common::LogLevel::DEBUG);
    GPP_LOG_INFO("MAIN", "==================================================================");
    GPP_LOG_INFO("MAIN", " 3GPP Test Suite - Lesson 2: 5G SBA (TLS 1.3 + HTTP/2 SBI) Test ");
    GPP_LOG_INFO("MAIN", "==================================================================");

    common::PcapWriter pcap("output_02_sba_http2.pcap");
    GPP_LOG_INFO("MAIN", "Writing captured 5G SBI transactions to 'output_02_sba_http2.pcap'...");

    // 1. Setup Server (Mock 5G NRF - Network Repository Function)
    sba::TlsContext server_ctx(sba::TlsContext::Role::SERVER);
    server_ctx.generate_self_signed_cert("nrf.5gc.mnc001.mcc001.3gppnetwork.org");
    server_ctx.set_alpn_protocols({"h2"});

    ip::TcpListener listener;
    if (!listener.listen("127.0.0.1", 0)) {
        GPP_LOG_ERROR("NRF_SERVER", "Failed to bind server port");
        return 1;
    }
    uint16_t server_port = listener.local_port();
    GPP_LOG_INFO("NRF_SERVER", "Mock 5G NRF listening on 127.0.0.1:" + std::to_string(server_port) + " (HTTPS / h2)");

    std::thread server_thread([&]() {
        ip::TcpSocket raw_client;
        std::string client_host;
        uint16_t client_port = 0;

        if (!listener.accept(raw_client, client_host, client_port, 3000)) {
            GPP_LOG_ERROR("NRF_SERVER", "Accept failed or timed out");
            return;
        }

        sba::TlsSocket tls_server(server_ctx);
        if (!tls_server.accept(std::move(raw_client))) {
            GPP_LOG_ERROR("NRF_SERVER", "TLS 1.3 handshake failed on server");
            return;
        }
        GPP_LOG_INFO("NRF_SERVER", "TLS Handshake complete! Version=" + tls_server.tls_version() +
                                   ", ALPN=" + tls_server.negotiated_alpn());

        sba::SbaSession session(tls_server, false /* is_server */);
        if (!session.perform_handshake(2000)) {
            GPP_LOG_ERROR("NRF_SERVER", "HTTP/2 connection handshake failed");
            return;
        }

        // Receive 5G NF Registration request
        auto req_opt = session.receive_request(2000);
        if (req_opt) {
            auto [stream_id, req] = *req_opt;
            GPP_LOG_INFO("NRF_SERVER", "Received 5G SBA Request on Stream #" + std::to_string(stream_id) +
                                       ": " + req.method + " " + req.path);
            GPP_LOG_INFO("NRF_SERVER", "Request Body: " + req.body);

            // Respond with 201 Created
            sba::SbaResponse resp;
            resp.status = 201;
            resp.content_type = "application/json";
            resp.body = "{\"nfInstanceId\": \"amf-01\", \"nfStatus\": \"REGISTERED\", \"heartBeatTimer\": 30}";
            session.send_response(stream_id, resp);
            GPP_LOG_INFO("NRF_SERVER", "Sent 5G SBA Response: 201 Created (REGISTERED)");
        }
    });

    // 2. Setup Client (Mock 5G AMF - Access and Mobility Management Function)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    sba::TlsContext client_ctx(sba::TlsContext::Role::CLIENT);
    client_ctx.set_alpn_protocols({"h2"});

    sba::TlsSocket tls_client(client_ctx);
    if (!tls_client.connect("127.0.0.1", server_port, 2000)) {
        GPP_LOG_ERROR("AMF_CLIENT", "Failed to connect to NRF via TLS 1.3");
        server_thread.join();
        return 1;
    }
    GPP_LOG_INFO("AMF_CLIENT", "Connected via TLS! Version=" + tls_client.tls_version() +
                               ", ALPN=" + tls_client.negotiated_alpn());

    sba::SbaSession client_session(tls_client, true /* is_client */);
    if (!client_session.perform_handshake(2000)) {
        GPP_LOG_ERROR("AMF_CLIENT", "HTTP/2 client handshake failed");
        server_thread.join();
        return 1;
    }

    // Prepare 3GPP TS 29.510 NFProfile for AMF
    sba::SbaRequest reg_request;
    reg_request.method = "POST";
    reg_request.path = "/nnrf-nfm/v1/nf-instances/amf-01";
    reg_request.authority = "nrf.5gc.mnc001.mcc001.3gppnetwork.org";
    reg_request.content_type = "application/json";
    reg_request.body = "{\"nfInstanceId\":\"amf-01\",\"nfType\":\"AMF\",\"nfStatus\":\"REGISTERED\","
                       "\"plmnList\":[{\"mcc\":\"001\",\"mnc\":\"01\"}],"
                       "\"ipv4Addresses\":[\"10.0.0.1\"]}";

    GPP_LOG_INFO("AMF_CLIENT", "Sending 3GPP TS 29.510 NFProfile Registration to NRF...");
    uint32_t stream_id = 1; // Client-initiated streams start at 1
    client_session.send_request(stream_id, reg_request);

    // Capture synthetic cleartext HTTP/2 frames to PCAP for Wireshark inspection
    {
        auto headers = sba::Hpack::encode({
            {":method", reg_request.method},
            {":scheme", reg_request.scheme},
            {":path", reg_request.path},
            {":authority", reg_request.authority},
            {":content-type", reg_request.content_type}
        });
        auto hdr_frame = sba::Http2Frame::make_headers(stream_id, headers, false);
        dump_frame_to_pcap(pcap, 54321, server_port, hdr_frame);

        std::span<const uint8_t> body_sp(reinterpret_cast<const uint8_t*>(reg_request.body.data()), reg_request.body.size());
        auto data_frame = sba::Http2Frame::make_data(stream_id, body_sp, true);
        dump_frame_to_pcap(pcap, 54321, server_port, data_frame);
    }

    // Await Response
    auto resp_opt = client_session.receive_response(2000);
    if (resp_opt) {
        GPP_LOG_INFO("AMF_CLIENT", "Received Response from NRF: HTTP Status " + std::to_string(resp_opt->status));
        GPP_LOG_INFO("AMF_CLIENT", "Response Body: " + resp_opt->body);

        // Capture response frame to PCAP
        auto resp_headers = sba::Hpack::encode({
            {":status", std::to_string(resp_opt->status)},
            {"content-type", resp_opt->content_type}
        });
        auto resp_hdr_frame = sba::Http2Frame::make_headers(stream_id, resp_headers, false);
        dump_frame_to_pcap(pcap, server_port, 54321, resp_hdr_frame);

        std::span<const uint8_t> resp_body_sp(reinterpret_cast<const uint8_t*>(resp_opt->body.data()), resp_opt->body.size());
        auto resp_data_frame = sba::Http2Frame::make_data(stream_id, resp_body_sp, true);
        dump_frame_to_pcap(pcap, server_port, 54321, resp_data_frame);
    }

    server_thread.join();
    pcap.close();
    GPP_LOG_INFO("MAIN", "Lesson 2 Complete! Generated 'output_02_sba_http2.pcap' with " +
                         std::to_string(pcap.packet_count()) + " packets.");
    return 0;
}
