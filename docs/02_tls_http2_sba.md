# Lesson 02: TLS 1.3 + HTTP/2 for 5G Service-Based Architecture (SBA)

## Overview

In **5G Core (5GC)** (3GPP TS 23.501 / TS 29.500), the control plane evolved from the legacy point-to-point Diameter interfaces of 4G LTE EPC into a **Service-Based Architecture (SBA)**. Every 5G Network Function (NF) exposes REST-like services that other NFs consume via **HTTP/2 over TLS 1.3 over TCP**.

This lesson covers:
- **TLS 1.3** (RFC 8446): 1-RTT handshake, ALPN negotiation for `h2`
- **HTTP/2** (RFC 7540 / RFC 9113): Binary framed multiplexed streams, HPACK header compression
- **5G SBI** (TS 29.500 / TS 29.510): NRF registration endpoint `POST /nnrf-nfm/v1/nf-instances`

### 3GPP Context

| Interface | Between | Purpose |
|-----------|---------|---------|
| **Nnrf** | AMF / SMF / UDM ↔ NRF | NF registration and discovery |
| **Namf** | SMF / NEF ↔ AMF | AM Policy, N1/N2 message transfer |
| **Nudm** | AMF / SMF ↔ UDM | Subscriber data retrieval |
| **Nsmf** | AMF ↔ SMF | PDU Session management |
| **Nausf** | AMF ↔ AUSF | 5G-AKA / EAP-AKA' authentication |

---

## 1. Protocol Structure

### TLS 1.3 Record (RFC 8446 §5.1)

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Content Type  |     Legacy Version (0x0303)   |    Length     |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Encrypted data (ApplicationData / Handshake fragments) ...   |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Key TLS 1.3 improvements over TLS 1.2:
- **1-RTT handshake**: `ClientHello` with key share → `ServerHello` + encrypted `{Certificate, CertVerify, Finished}` → client `Finished`
- Removed RSA key exchange; only (EC)DHE forward-secret ciphers allowed
- **ALPN extension**: Client advertises `h2` in ClientHello; server confirms in EncryptedExtensions

### HTTP/2 Frame Header (RFC 7540 §4.1) — 9 bytes

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Length (24 bits)           |   Type (8)    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |   Flags (8)   |R|         Stream Identifier (31 bits)         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Frame Type | ID | Purpose |
|------------|----|---------|
| `DATA` | 0x0 | Request/response body payload |
| `HEADERS` | 0x1 | HPACK-compressed header block |
| `SETTINGS` | 0x4 | Connection parameters exchange |
| `PING` | 0x6 | Keepalive / RTT measurement |
| `GOAWAY` | 0x7 | Graceful connection shutdown |
| `WINDOW_UPDATE` | 0x8 | Flow control credit |

---

## 2. 3GPP Protocol Flow

### 5G AMF → NRF Registration (TS 29.510)

```
    AMF (Consumer)                           NRF (Producer)
         |                                          |
         | 1. TCP Connect                           |
         |----------------------------------------->|
         |                                          |
         | 2. TLS 1.3 Handshake (ALPN: h2)         |
         |<========================================>|
         |                                          |
         | 3. HTTP/2 Connection Preface             |
         |   PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n      |
         |----------------------------------------->|
         |                                          |
         | 4. SETTINGS frame (stream 0)             |
         |<========================================>|
         |                                          |
         | 5. POST /nnrf-nfm/v1/nf-instances/amf-01|
         |   HEADERS: :method=POST, :scheme=https   |
         |   DATA: {"nfType":"AMF","nfStatus":...}  |
         |----------------------------------------->|
         |                                          |
         | 6. HTTP/2 201 Created                    |
         |   HEADERS: :status=201                   |
         |   DATA: {"nfStatus":"REGISTERED",...}    |
         |<-----------------------------------------|
```

### HPACK Static Table Entries Used (RFC 7541 §B)

| Index | Header Name | Value |
|-------|------------|-------|
| 1 | `:authority` | — |
| 2 | `:method` | `GET` |
| 3 | `:method` | `POST` |
| 8 | `:status` | `200` |
| 31 | `content-type` | — |

---

## 3. Project Implementation

### Source Files

| File | Description |
|------|-------------|
| `include/3gpp/sba/Http2Frame.hpp` | 9-byte frame header, frame type factories (SETTINGS, PING, GOAWAY, HEADERS, DATA) |
| `include/3gpp/sba/Hpack.hpp` | HPACK static table, integer variable-prefix encode/decode, header encode/decode |
| `include/3gpp/sba/TlsSocket.hpp` | OpenSSL TLS 1.3 wrapper — ALPN `h2`, in-memory self-signed X.509 cert generation |
| `include/3gpp/sba/SbaSession.hpp` | HTTP/2 connection handshake, SBI request/response helper |

### Demo Scenario — `demo_02_sba_http2.cpp`

Simulates an **AMF → NRF** 5G SBI registration over a real TLS 1.3 loopback:

1. **TLS Handshake** — AMF (client) negotiates TLS 1.3 with ALPN `h2` to NRF (server)
2. **HTTP/2 Preface** — both sides exchange connection magic + SETTINGS frames
3. **POST request** — AMF sends `POST /nnrf-nfm/v1/nf-instances/amf-01` with JSON body
4. **201 Created** — NRF responds with `REGISTERED` status
5. All frames captured to `output_02_sba_http2.pcap`

---

## 4. Key Engineering Concepts

### ALPN — Application-Layer Protocol Negotiation
ALPN (RFC 7301) is a TLS extension that allows the client to list supported application protocols (`h2`, `http/1.1`) in the ClientHello. The server selects one and confirms in its EncryptedExtensions. This eliminates the need for an extra round-trip to upgrade from HTTP/1.1 to HTTP/2.

### HPACK Integer Variable-Length Prefix Encoding
HTTP/2 header field indices and string lengths use a variable-length integer with a configurable `N`-bit prefix (1–8 bits). If the value fits in `2^N - 1` bits, it is encoded inline. Otherwise, the prefix bits are all set to 1 and the remainder is encoded in subsequent octets with 7 bits per octet and a continuation bit.

### HTTP/2 Stream Multiplexing
All HTTP/2 requests and responses share a single TLS connection as independent streams, each identified by an odd stream ID (client-initiated). Stream 0 is reserved for connection-level control frames (SETTINGS, PING, GOAWAY, WINDOW_UPDATE).

---

## 5. Wireshark Analysis

Open `output_02_sba_http2.pcap` and verify:

```
Frame 1: AMF → NRF   TLS Application Data  [HTTP/2 Connection Preface + SETTINGS]
Frame 2: NRF → AMF   TLS Application Data  [HTTP/2 SETTINGS ACK]
Frame 3: AMF → NRF   TLS Application Data  [HTTP/2 HEADERS POST /nnrf-nfm/v1/nf-instances/amf-01]
Frame 4: AMF → NRF   TLS Application Data  [HTTP/2 DATA {"nfType":"AMF",...}]
Frame 5: NRF → AMF   TLS Application Data  [HTTP/2 HEADERS :status 201]
Frame 6: NRF → AMF   TLS Application Data  [HTTP/2 DATA {"nfStatus":"REGISTERED",...}]
```

In Wireshark: right-click a packet → **Decode As → HTTP2** to inspect:
- `HTTP2: HEADERS (1) (END_HEADERS) :method: POST :path: /nnrf-nfm/v1/nf-instances/amf-01`
- `HTTP2: DATA (0) (END_STREAM) {"nfInstanceId":"amf-01", ...}`

```bash
tcpdump -r output_02_sba_http2.pcap -nvX
```

---

## 6. Test Cases (`test_02_sba_http2.cpp`)

| Test | Description |
|------|-------------|
| `Http2Test.FrameHeaderRoundTrip` | 9-byte HTTP/2 frame header encode → decode round-trip |
| `Http2Test.SettingsFrameFactory` | SETTINGS frame construction and ACK flag |
| `Http2Test.PingAndGoawayFrames` | PING opaque data and GOAWAY last-stream-id |
| `HpackTest.IntegerVariablePrefix` | HPACK variable-prefix integer encode/decode at N=1,4,5,8 |
| `HpackTest.HeadersEncodeDecodeRoundTrip` | Full HPACK static-table header block encode → decode |
| `SbaTest.Tls13AlpnHandshakeAndEcho` | Live TLS 1.3 loopback with ALPN `h2` negotiation and echo |

---

## 7. References

| Specification | Title |
|--------------|-------|
| **RFC 8446** | TLS 1.3 |
| **RFC 7540** | HTTP/2 |
| **RFC 9113** | HTTP/2 (updated) |
| **RFC 7541** | HPACK — Header Compression for HTTP/2 |
| **RFC 7301** | TLS ALPN Extension |
| **3GPP TS 23.501** | System Architecture for the 5G System |
| **3GPP TS 29.500** | 5G System — Technical Realization of Service-Based Architecture |
| **3GPP TS 29.510** | NF Repository Function (NRF) Services |
| **3GPP TS 33.501** | Security Architecture and Procedures for 5G System |
