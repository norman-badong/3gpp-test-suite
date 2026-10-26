# Lesson 01: IP Networking (IPv4, IPv6, UDP, TCP)

## 1. 3GPP Relevance & Architecture Context

In 3GPP systems (4G LTE EPS and 5G System), all end-user mobile data (web browsing, streaming, VoLTE/VoNR audio packets) and control signaling rely on IP transport:

- **GTP-U Bearer Transport (TS 29.281):** Between the gNB/eNB (Base Station) and the UPF/S-GW (Core User Plane Function), user packets are encapsulated inside UDP datagrams destined for port `2152` (GPRS Tunneling Protocol User Plane).
- **5G Service-Based Architecture (TS 23.501 / TS 29.500):** All 5G Core control plane network functions (AMF, SMF, UDM, AUSF, NRF) communicate using HTTP/2 over TLS over **TCP**.
- **Dual-Stack User Plane (IPv4v6):** 3GPP devices request PDU sessions with session types `IPv4`, `IPv6`, or `IPv4v6`. The baseband protocol stack must parse and construct valid IPv4 and IPv6 packet headers without corrupting checksums or fragmentation offsets.

```
+-------------------------------------------------------------+
|               End-User IP Packet (IPv4 or IPv6)             |
+-------------------------------------------------------------+
|               GTP-U Header (TS 29.281, TEID)                |
+-------------------------------------------------------------+
|         UDP Header (Port 2152) [RFC 768]                    |
+-------------------------------------------------------------+
|         Transport IP Header (gNB <-> UPF) [RFC 791 / 8200]  |
+-------------------------------------------------------------+
|         Ethernet / L2 Transport Frame                       |
+-------------------------------------------------------------+
```

---

## 2. Protocol Standards Implemented

### RFC 791 (IPv4)
- **Version (4 bits) & IHL (4 bits):** Minimum header length is 20 bytes (IHL = 5).
- **DSCP / ECN (8 bits):** Quality of Service marking (mapped from 3GPP 5QI / QCI).
- **Total Length (16 bits):** Header size + payload size.
- **Identification & Flags (DF, MF):** MTU handling and packet fragmentation control.
- **TTL (Time to Live, 8 bits):** Decremented per hop.
- **Protocol (8 bits):** `17` for UDP, `6` for TCP, `1` for ICMP.
- **Header Checksum (16 bits):** One's complement sum of all 16-bit words (RFC 1071).
- **Source & Destination IPv4:** 32-bit network byte order addresses.

### RFC 8200 (IPv6)
- **Version (4 bits = 6), Traffic Class (8 bits), Flow Label (20 bits):** Simplified fixed 40-byte header without hop-by-hop checksum for high throughput.
- **Payload Length (16 bits):** Excludes the 40-byte header.
- **Next Header (8 bits):** Replaces IPv4 protocol field.
- **Source & Destination IPv6:** 128-bit addresses (`[2001:db8::1]`).

### RFC 768 (UDP)
- Lightweight 8-byte header: Source Port, Destination Port, Length, Checksum.
- **Pseudo-Header Checksum:** Includes IP source, destination, protocol, and length to ensure datagrams are not misdelivered to wrong endpoints.

### RFC 793 (TCP)
- Connection-oriented streaming with 3-way handshake (`SYN` $\rightarrow$ `SYN-ACK` $\rightarrow$ `ACK`).
- Flags: `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`.
- Sequence and Acknowledgment numbers tracking transmitted bytes.

---

## 3. How to Run the Tests & Inspect Output

### Run Unit Tests
```bash
./build/tests/unit_tests --gtest_filter="*Ip*"
```

### Run Standalone Demo
```bash
./build/apps/demo_01_ip_echo
```

### Inspect Output in Wireshark / tcpdump
The application exports a standard PCAP file `output_01_ip_echo.pcap`:
```bash
tcpdump -r output_01_ip_echo.pcap -nvX
```
Wireshark will recognize the captured packets as standard Ethernet/IP/UDP and TCP frames with verified checksums.
