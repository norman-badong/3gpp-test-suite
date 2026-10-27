# Lesson 06: Diameter Protocol — LTE EPC & IMS S6a Interface

## Overview

**Diameter** (RFC 6733) is the Authentication, Authorization, and Accounting (AAA) protocol that replaced RADIUS in 3GPP LTE/IMS networks. It runs over **TCP port 3868** and uses a binary TLV (Type-Length-Value) framing called **AVPs** (Attribute-Value Pairs). Every LTE subscriber authentication, policy enforcement, and charging action passes through at least one Diameter interface.

This lesson covers:
- Diameter Base Protocol framing — 20-byte header, AVP encoding with 4-byte alignment
- **CER/CEA**: Capabilities-Exchange-Request/Answer — peer capability negotiation
- **DWR/DWA**: Device-Watchdog-Request/Answer — keepalive heartbeat
- **S6a AIR/AIA**: Authentication-Information-Request/Answer — the core of LTE Attach authentication (RAND, XRES, AUTN, KASME)

### 3GPP Context

| Interface | Between | Purpose |
|-----------|---------|---------|
| **S6a** | MME ↔ HSS | LTE subscriber authentication & profile download |
| **S6d** | SGSN ↔ HSS | 3G/UMTS equivalent of S6a |
| **Cx/Dx** | P-CSCF/I-CSCF ↔ HSS | IMS subscriber registration |
| **Gx** | PCEF ↔ PCRF | QoS policy control |
| **Gy/Ro** | OCS ↔ P-GW | Online Charging System (RFC 4006) |

---

## 1. Protocol Structure

### Diameter Message Header (RFC 6733 §3) — 20 bytes fixed

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |    Version    |                 Message Length                 |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |R P E T r r r r|               Command-Code                    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         Application-ID                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                      Hop-by-Hop Identifier                    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                      End-to-End Identifier                    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  AVPs ...
 +-+-+-+-+-+-+-+-+-
```

| Flag | Bit | Meaning |
|------|-----|---------|
| `R` | 7 | Request (1) or Answer (0) |
| `P` | 6 | Proxiable — may be forwarded by Diameter agents |
| `E` | 5 | Error Response |
| `T` | 4 | Potentially Retransmitted |

### AVP Format (RFC 6733 §4.1)

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                           AVP Code                            |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |V M P r r r r r|                  AVP Length                   |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                  Vendor-ID (optional, if V=1)                 |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |    Data ...  (padded to 4-byte boundary with zeros)
 +-+-+-+-+-+-+-+-+
```

| Rule | Detail |
|------|--------|
| `V=1` → 12-byte header | Adds 4-byte Vendor-ID field |
| `V=0` → 8-byte header | Standard base protocol AVPs |
| 3GPP Vendor-ID | `10415` (0x000028AF) |
| Padding | Zero-bytes to next 4-byte boundary; **NOT** counted in AVP Length |

---

## 2. 3GPP Protocol Flow

### LTE Attach — S6a Authentication Flow (TS 23.401 §5.3.2.1)

```
UE                  MME                           HSS
 |                   |                             |
 |--Attach Request-->|                             |
 |                   |---CER (Capabilities)------->|
 |                   |<--CEA (Result=2001)---------|
 |                   |                             |
 |                   |---S6a AIR (IMSI, PLMN)----->|
 |                   |<--S6a AIA (RAND/AUTN/       |
 |                   |          XRES/KASME)---------|
 |                   |                             |
 |<--Auth Request----|                             |
 |---RES------------>|                             |
 |                   | (MME verifies RES == XRES)  |
 |                   |                             |
 |                   |---DWR (keepalive)---------->|
 |                   |<--DWA (Result=2001)---------|
```

### Key AVPs — S6a AIR (Authentication-Information-Request)

| AVP | Code | Vendor | Purpose |
|-----|------|--------|---------|
| Session-Id | 263 | — | Unique Diameter session identifier |
| Auth-Session-State | 277 | — | `1` = NO_STATE_MAINTAINED |
| User-Name | 1 | — | IMSI of the subscriber |
| Visited-PLMN-Id | 1407 | 10415 | 3-byte MCC-MNC of visited network |
| Requested-EUTRAN-Auth-Info | 1401 | 10415 | Grouped: number of vectors requested |

### Key AVPs — S6a AIA (Authentication-Information-Answer)

| AVP | Code | Vendor | Purpose |
|-----|------|--------|---------|
| Result-Code | 268 | — | `2001` = DIAMETER_SUCCESS |
| Authentication-Info | 1413 | 10415 | Grouped containing E-UTRAN-Vectors |
| E-UTRAN-Vector | 1414 | 10415 | Grouped: RAND, XRES, AUTN, KASME |
| RAND | 1447 | 10415 | 16-byte random challenge |
| XRES | 1448 | 10415 | 8-byte expected UE response |
| AUTN | 1449 | 10415 | 16-byte authentication token |
| KASME | 1450 | 10415 | 32-byte K_ASME root key |

---

## 3. Project Implementation

### Source Files

| File | Description |
|------|-------------|
| `include/3gpp/diameter/DiameterAvp.hpp` | AVP flags, codes, factory methods, encode/decode with 4-byte alignment |
| `include/3gpp/diameter/DiameterMessage.hpp` | 20-byte header, command codes, application IDs, AVP list |
| `include/3gpp/diameter/DiameterFactory.hpp` | High-level builders: CER/CEA, DWR/DWA, S6a AIR/AIA |
| `include/3gpp/diameter/DiameterStack.hpp` | TCP stream framer: length-prefixed send/receive over socket |

### Demo Scenario — `demo_06_diameter_s6a.cpp`

Simulates an **MME ↔ HSS** Diameter S6a exchange over a real TCP loopback socket:

1. **CER** → MME announces support for App-ID `16777251` (3GPP S6a)
2. **CEA** ← HSS replies with `DIAMETER_SUCCESS (2001)`
3. **S6a AIR** → MME requests auth vectors for `IMSI 001010123456789` in `PLMN 001-01`
4. **S6a AIA** ← HSS provides one E-UTRAN vector (RAND + XRES + AUTN + KASME)
5. **DWR** → MME sends keepalive heartbeat
6. **DWA** ← HSS responds `2001`
7. All 6 packets captured to `output_06_diameter_s6a.pcap`

---

## 4. Key Engineering Concepts

### AVP 4-Byte Alignment Rule
Every AVP's wire footprint must start on a 4-byte boundary. Padding bytes of value `0x00` are appended **after** the data but are **NOT** included in the AVP Length field:
```
AVP Length = header_size + data_size          (excludes padding)
Wire size  = header_size + data_size + pad    (rounded up to multiple of 4)
```

### Grouped AVP Pattern
3GPP AVPs like `Authentication-Info` → `E-UTRAN-Vector` → `{RAND, XRES, AUTN, KASME}` are **Grouped** — their data payload is itself a concatenation of serialized child AVPs. Decoding is fully recursive.

### Hop-by-Hop vs End-to-End Identifiers
- **Hop-by-Hop ID**: Rewritten at each Diameter agent hop; used to correlate a Request to its Answer within one transport hop
- **End-to-End ID**: Preserved across all hops end-to-end; used for retransmission duplicate detection

### DIAMETER_SUCCESS = 2001
The Diameter Result-Code `2001` (DIAMETER_SUCCESS) is the equivalent of HTTP `200 OK`. Any other value in the 2xxx range is also a success class; values in 3xxx/4xxx/5xxx are error codes.

---

## 5. Wireshark Analysis

Open `output_06_diameter_s6a.pcap` and verify:

```
Frame 1: MME → HSS   Capabilities-Exchange Request     (CER, App-ID=0)
Frame 2: HSS → MME   Capabilities-Exchange Answer      (CEA, Result=2001)
Frame 3: MME → HSS   3GPP-Authentication-Info Request  (AIR, App-ID=16777251)
Frame 4: HSS → MME   3GPP-Authentication-Info Answer   (AIA, Result=2001)
Frame 5: MME → HSS   Device-Watchdog Request            (DWR)
Frame 6: HSS → MME   Device-Watchdog Answer             (DWA, Result=2001)
```

In Wireshark: expand **Frame 4 → Diameter Protocol → Authentication-Info → E-UTRAN-Vector** to see the full RAND, XRES, AUTN, and KASME byte values in decoded form. The Diameter dissector automatically recognizes AVP codes 1413/1414/1447–1450 as 3GPP S6a fields.

```bash
tcpdump -r output_06_diameter_s6a.pcap -nv
```

---

## 6. Test Cases (`test_06_diameter.cpp`)

| Test | Description |
|------|-------------|
| `DiameterAvpTest.Unsigned32EncodingDecoding` | AVP round-trip for Unsigned32 — Result-Code `2001` |
| `DiameterAvpTest.StringAndPadding` | 5-byte string AVP serializes to 16 bytes (8 header + 5 data + 3 pad) |
| `DiameterAvpTest.VendorSpecificAvp` | Visited-PLMN-Id with Vendor-ID=10415 encode/decode |
| `DiameterAvpTest.GroupedAvp` | Grouped parent AVP ↔ children round-trip decode |
| `DiameterMessageTest.CapabilitiesExchangeRoundTrip` | Full CER encode → CEA decode; verify all AVPs |
| `DiameterMessageTest.WatchdogRoundTrip` | DWR → DWA hop/e2e ID preservation |
| `DiameterS6aTest.AirAiaAuthenticationVectors` | Complete AIR → AIA with RAND/XRES/AUTN/KASME verify |
| `DiameterConnectionTest.LoopbackCERExchange` | Live TCP CER/CEA over loopback socket (threaded) |

---

## 7. References

| Specification | Title |
|--------------|-------|
| **RFC 6733** | Diameter Base Protocol |
| **RFC 4006** | Diameter Credit-Control Application (Gy/Ro) |
| **3GPP TS 29.272** | S6a/S6d Diameter Application for MME ↔ HSS |
| **3GPP TS 29.230** | Diameter Applications — 3GPP AVP Code Allocation |
| **3GPP TS 33.401** | SAE Security Architecture — MILENAGE & K_ASME derivation |
| **3GPP TS 23.401** | GPRS Enhancements for E-UTRAN Access — LTE Attach procedure |
