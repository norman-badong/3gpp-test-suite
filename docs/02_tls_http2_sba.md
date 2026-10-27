# Lesson 02: TLS 1.3 + HTTP/2 for 5G Service-Based Architecture (SBA)

## 1. 3GPP Relevance & Architecture Context

In **5G Core (5GC)** defined in 3GPP TS 23.501 and TS 29.500, the control plane radically evolved from legacy point-to-point Diameter interfaces (used in 4G LTE EPC) into a **Service-Based Architecture (SBA)**.

In SBA:
- Every 5G Network Function (NF) produces services that other NFs consume via **Service-Based Interfaces (SBI)**.
- Transport Protocol: **HTTP/2 (RFC 7540 / RFC 9113) over TLS 1.3 (RFC 8446) over TCP**.
- Payload Serialization: **JSON (RFC 8259)**.
- Interface Naming: e.g., `Nnrf` (NRF services), `Namf` (AMF services), `Nsmf` (SMF services), `Nudm` (UDM services).

```
+-------------+                     +-------------+
|   5G AMF    |                     |   5G NRF    |
| (Consumer)  |                     | (Producer)  |
+------+------+                     +------+------+
       |                                   |
       |  1. TLS 1.3 Handshake (ALPN: h2)  |
       |<=================================>|
       |                                   |
       |  2. HTTP/2 Preface & SETTINGS     |
       |<--------------------------------->|
       |                                   |
       |  3. POST /nnrf-nfm/v1/nf-instances|
       |     [HEADERS + DATA (JSON)]       |
       |---------------------------------->|
       |                                   |
       |  4. 201 Created                   |
       |     [HEADERS + DATA (JSON)]       |
       |<----------------------------------|
```

---

## 2. Key Specifications Implemented

### RFC 8446 (TLS 1.3)
- Mandatory for 5G Core inter-NF communication per 3GPP TS 33.501.
- TLS 1.3 removes obsolete cryptographic algorithms and completes the handshake in 1-RTT.
- **ALPN (Application-Layer Protocol Negotiation):** During the ClientHello / EncryptedExtensions handshake, both client and server negotiate `h2` ("HTTP/2 over TLS").

### RFC 7540 / RFC 9113 (HTTP/2)
- **Connection Preface:** 24-octet sequence `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`.
- **9-Octet Frame Header:**
  - Length (24 bits)
  - Frame Type (8 bits): `DATA`, `HEADERS`, `SETTINGS`, `PING`, `GOAWAY`, etc.
  - Flags (8 bits): `END_STREAM (0x01)`, `END_HEADERS (0x04)`, `ACK (0x01)`.
  - Stream ID (31 bits).
- **HPACK Compression (RFC 7541):** Header compression utilizing a 61-entry Static Table and indexed literal encoding for pseudo-headers (`:method`, `:path`, `:scheme`, `:status`, `:authority`).

### 3GPP TS 29.510 (NRF Management Service)
- Endpoint: `POST /nnrf-nfm/v1/nf-instances/{nfInstanceId}`
- Body: `NFProfile` specifying NF type (`AMF`), status (`REGISTERED`), PLMN identities (MCC/MNC), and IPv4/IPv6 endpoints.

---

## 3. How to Run the Tests & Inspect Output

### Run Unit Tests
```bash
./build/tests/unit_tests --gtest_filter="*Http2*:*Hpack*:*Sba*"
```

### Run Standalone Demo
```bash
./build/apps/demo_02_sba_http2
```

### Inspect Output in Wireshark / tcpdump
```bash
tcpdump -r output_02_sba_http2.pcap -nvX
```
Wireshark dissects the frames into:
- `HTTP2: HEADERS (1) (END_HEADERS) :method: POST, :path: /nnrf-nfm/v1/nf-instances/amf-01`
- `HTTP2: DATA (0) (END_STREAM) {"nfInstanceId":"amf-01", ...}`
- `HTTP2: HEADERS (1) (END_HEADERS) :status: 201`
- `HTTP2: DATA (0) (END_STREAM) {"nfStatus": "REGISTERED", ...}`
