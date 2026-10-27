# Lesson 01: IP Networking (IPv4, IPv6, UDP, TCP)

## Overview

**IP Networking** is the universal transport foundation of all 3GPP cellular protocols. Every control-plane signal and user-plane data packet in 4G LTE and 5G NR travels as an IP datagram at some layer of the stack — whether it is a raw UDP payload carrying GTP-U tunneled user data, or a TCP segment carrying a TLS-encrypted HTTP/2 NF-to-NF API call in the 5G Core.

This lesson covers:
- **IPv4** (RFC 791): 20-byte header with checksum, fragmentation, TTL, and protocol field
- **IPv6** (RFC 8200): 40-byte fixed header with Flow Label for QoS and Next-Header extension chain
- **UDP** (RFC 768): 8-byte lightweight datagram transport with pseudo-header checksum
- **TCP** (RFC 793): Reliable, ordered, connection-oriented stream with full flag set

### 3GPP Context

| Interface | Between | Transport | Purpose |
|-----------|---------|-----------|---------|
| **GTP-U (S1-U / N3)** | eNB/gNB ↔ S-GW/UPF | UDP/IPv4 or IPv6 | User-plane data tunnel (port 2152) |
| **5G SBI (Nxx)** | AMF / SMF / NRF etc. | TCP/IPv4 or IPv6 | HTTP/2 service-based interface |
| **S1-MME / N2** | eNB/gNB ↔ MME/AMF | SCTP/IP | Control-plane signaling |
| **IMS Signaling** | UE ↔ P-CSCF | UDP or TCP | SIP/SDP over IP |

---

## 1. Protocol Structure

### IPv4 Header (RFC 791)

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |Version|  IHL  |    DSCP   |ECN|         Total Length          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |         Identification        |Flags|      Fragment Offset     |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Time to Live |    Protocol   |        Header Checksum        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                       Source Address                          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Destination Address                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Total header: 20 bytes** (minimum, no options)

| Field | Bits | 3GPP Relevance |
|-------|------|----------------|
| **Version** | 4 | `4` for IPv4 |
| **IHL** | 4 | `5` = 20 bytes (no options) |
| **DSCP / ECN** | 8 | Mapped from 3GPP 5QI/QCI for QoS marking |
| **Total Length** | 16 | Header + payload size |
| **Flags (DF, MF)** | 3 | `DF=1` (Don't Fragment) commonly set in cellular |
| **TTL** | 8 | Decremented per hop; prevents routing loops |
| **Protocol** | 8 | `6`=TCP, `17`=UDP, `1`=ICMP, `132`=SCTP |
| **Header Checksum** | 16 | RFC 1071 one's complement sum |

### IPv6 Header (RFC 8200)

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |Version| Traffic Class |           Flow Label                  |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |         Payload Length        |  Next Header  |   Hop Limit   |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                   Source Address (128 bits)                   |
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                Destination Address (128 bits)                 |
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Total header: 40 bytes** (fixed, no checksum field)

### UDP Header (RFC 768) — 8 bytes

```
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |       Source Port             |     Destination Port          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |          Length               |           Checksum            |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### TCP Flags (RFC 793)

| Flag | Hex | Purpose |
|------|-----|---------|
| `SYN` | 0x02 | Initiate connection (3-way handshake) |
| `ACK` | 0x10 | Acknowledge received bytes |
| `FIN` | 0x01 | Graceful connection teardown |
| `RST` | 0x04 | Abrupt reset |
| `PSH` | 0x08 | Push buffered data to application immediately |

---

## 2. 3GPP Protocol Flow

### GTP-U User-Plane Encapsulation (S1-U / N3 Interface)

```
+-------------------------------------------------------------+
|        End-User IP Packet (IPv4 or IPv6)  [Application]    |
+-------------------------------------------------------------+
|        GTP-U Header (TS 29.281, TEID)    [Tunneling]       |
+-------------------------------------------------------------+
|        UDP Header (Port 2152)             [RFC 768]         |
+-------------------------------------------------------------+
|        Transport IP Header (gNB ↔ UPF)   [RFC 791 / 8200]  |
+-------------------------------------------------------------+
|        Ethernet / L2 Transport Frame      [Link Layer]      |
+-------------------------------------------------------------+
```

### Dual-Stack PDU Session (TS 23.502)

```
UE                gNB              SMF              UPF
 |---PDU Session Req (IPv4v6)---->|                  |
 |                                |--N4 Session Est->|
 |<--PDU Session Accept-----------|  (IPv4+IPv6 pool)|
 |   [UE IPv4: 10.x.x.x]         |                  |
 |   [UE IPv6: 2001:db8::x]       |                  |
```

---

## 3. Project Implementation

### Source Files

| File | Description |
|------|-------------|
| `include/3gpp/ip/IpAddress.hpp` | `Ipv4Address` and `Ipv6Address` types with from/to string |
| `include/3gpp/ip/Checksum.hpp` | RFC 1071 checksum + IPv4/IPv6 pseudo-header for UDP/TCP |
| `include/3gpp/ip/Ipv4Header.hpp` | Complete IPv4 header encoder/decoder |
| `include/3gpp/ip/Ipv6Header.hpp` | Complete IPv6 header encoder/decoder |
| `include/3gpp/ip/UdpPacket.hpp` | UDP header with pseudo-header checksum |
| `include/3gpp/ip/TcpPacket.hpp` | TCP header with all 8 flags and options |
| `include/3gpp/ip/Socket.hpp` | POSIX `UdpSocket`, `TcpSocket`, `TcpListener` wrappers |

### Demo Scenario — `demo_01_ip_echo.cpp`

Demonstrates IPv4/IPv6/UDP/TCP on a loopback socket:

1. **UDP Echo** — client sends a datagram, server echoes it back; both captured to PCAP
2. **TCP Transfer** — client connects via 3-way handshake, sends payload, server echoes, connection torn down with FIN/ACK
3. **IPv4 + IPv6 headers** built manually with correct RFC 1071 checksums
4. All packets exported to `output_01_ip_echo.pcap`

---

## 4. Key Engineering Concepts

### RFC 1071 Checksum Algorithm
The IPv4 header checksum (and UDP/TCP pseudo-header checksum) is a 16-bit one's complement sum of all 16-bit words. A correct receiver recomputes the sum over the entire header including the checksum field — the result must be `0xFFFF`.

### Pseudo-Header Checksum (UDP & TCP)
UDP and TCP checksums are computed over a **pseudo-header** prepended before the actual header:
```
[Src IP] [Dst IP] [Zero] [Protocol] [UDP/TCP Length]
```
This binds the transport segment to the correct IP endpoints and prevents misdelivery.

### IPv6 Eliminates Header Checksum
IPv6 removes the per-hop header checksum (covered by link-layer CRC instead) to reduce router processing overhead — a design choice that accelerates high-throughput 5G user-plane forwarding.

---

## 5. Wireshark Analysis

Open `output_01_ip_echo.pcap` and verify:

```
Frame 1:  127.0.0.1 → 127.0.0.2   UDP   [Echo Request payload]
Frame 2:  127.0.0.2 → 127.0.0.1   UDP   [Echo Response payload]
Frame 3:  10.0.0.1  → 10.0.0.2    TCP   [SYN]
Frame 4:  10.0.0.2  → 10.0.0.1    TCP   [SYN, ACK]
Frame 5:  10.0.0.1  → 10.0.0.2    TCP   [ACK, PSH - data]
```

In Wireshark: right-click any packet → **Follow → TCP Stream** to view the full byte stream. The **Checksum Status** column confirms all checksums pass.

```bash
tcpdump -r output_01_ip_echo.pcap -nvX
```

---

## 6. Test Cases (`test_01_ip.cpp`)

| Test | Description |
|------|-------------|
| `IpTest.AddressParsing` | IPv4 and IPv6 address parse/format round-trip |
| `IpTest.ChecksumRFC1071` | RFC 1071 checksum computation against known vectors |
| `IpTest.Ipv4HeaderRoundTrip` | Encode IPv4 header → decode → compare all fields |
| `IpTest.Ipv6HeaderRoundTrip` | Encode IPv6 header → decode → compare all fields |
| `IpTest.UdpPacketEncodingWithChecksum` | UDP encode with pseudo-header checksum verification |
| `IpTest.TcpPacketFlagsAndRoundTrip` | TCP flag encoding (SYN, ACK, FIN, RST, PSH) + decode |
| `SocketTest.UdpLoopbackEcho` | Live UDP send/receive on loopback socket |
| `SocketTest.TcpLoopbackTransfer` | Live TCP connect/send/receive/close on loopback |

---

## 7. References

| Specification | Title |
|--------------|-------|
| **RFC 791** | Internet Protocol version 4 (IPv4) |
| **RFC 8200** | Internet Protocol version 6 (IPv6) |
| **RFC 768** | User Datagram Protocol (UDP) |
| **RFC 793** | Transmission Control Protocol (TCP) |
| **RFC 1071** | Computing the Internet Checksum |
| **3GPP TS 29.281** | GPRS Tunnelling Protocol User Plane (GTP-U) |
| **3GPP TS 23.501** | System Architecture for 5G System |
| **3GPP TS 23.502** | Procedures for 5G System |
