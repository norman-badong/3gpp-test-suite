# Lesson 08: 5G NR Registration — 5GS Non-Access Stratum (5GMM & 5GSM)

## Overview

In the 5G System (5GS), the **Non-Access Stratum (NAS)** protocol connects the User Equipment (UE) directly to the **Access and Mobility Management Function (AMF)** and the **Session Management Function (SMF)** in the 5G Core (5GC) over the **N1** reference point (TS 23.501, TS 24.501).

5G NAS is divided into two distinct sub-layers:
1. **5GS Mobility Management (5GMM)** (Extended Protocol Discriminator `0x7E`): Handles UE registration, deregistrations, mobility updates, identity concealment, authentication (5G-AKA / EAP-AKA'), and NAS security contexts.
2. **5GS Session Management (5GSM)** (Extended Protocol Discriminator `0x2E`): Manages end-to-end user-plane PDU Sessions, assigning IP addresses, network slice contexts (S-NSSAI), and QoS Flow rules (QFI/5QI).

Unlike 4G LTE which exposed the subscriber's raw IMSI during the initial attach, 5G mandates **Subscriber Privacy**: the raw Subscription Permanent Identifier (SUPI) is concealed into a **Subscription Concealed Identifier (SUCI)** over the air interface.

---

### 3GPP Context

| Interface / Layer | Between | Role & Purpose |
|-------------------|---------|----------------|
| **N1 (5GMM)** | UE ↔ AMF | 5GS Registration, Identity verification, Service Requests, Security Mode |
| **N1 (5GSM)** | UE ↔ SMF (via AMF) | PDU Session Establishment, Modification, and Release |
| **N2** | gNodeB ↔ AMF | NG-AP signaling encapsulating N1 NAS messages (TS 38.413) |
| **N3** | gNodeB ↔ UPF | GTP-U user plane carrying subscriber PDU Session packets (TS 29.281) |
| **SBI (Namf/Nsmf)** | AMF ↔ SMF | Service Based Architecture over HTTP/2 + JSON (TS 29.502, Lesson 02) |

---

## 1. Protocol Structure

### Plain 5GMM Header (TS 24.501 §9.1.1) — 3 octets

```
  0                   1                   2
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |      EPD      |  Sec Hdr Type |     Spare     |  Message Type  |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| **Extended Protocol Discriminator (EPD)** | 8 bits | `0x7E` = 5GS Mobility Management (5GMM) |
| **Security Header Type** | 4 bits | `0x0` = Plain NAS (not security protected), `0x1` = Integrity protected, `0x2` = Ciphered |
| **Spare Half Octet** | 4 bits | Set to `0x0` |
| **Message Type** | 8 bits | Identifies 5GMM procedure (`0x41` = Registration Request, `0x42` = Registration Accept, `0x43` = Registration Complete) |

### 5GSM Header (TS 24.501 §9.1.2) — 4 octets

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |      EPD      |  PDU Sess ID  | Proc Trans ID |  Message Type  |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| **Extended Protocol Discriminator (EPD)** | 8 bits | `0x2E` = 5GS Session Management (5GSM) |
| **PDU Session Identity (PSI)** | 8 bits | Uniquely identifies the session (value `1` to `15`) |
| **Procedure Transaction Identity (PTI)** | 8 bits | Correlates requests and answers (e.g. `1`) |
| **Message Type** | 8 bits | `0xC1` = PDU Session Establishment Request, `0xC2` = PDU Session Establishment Accept |

---

## 2. 3GPP Protocol Flow

### 5G Standalone (SA) Initial Registration Sequence (TS 23.502 §4.2.2.2)

```
UE                                  AMF                                  SMF
 |                                   |                                    |
 |===== 1. Registration Request ====>|                                    |
 |   (5GMM: SUCI, ngKSI, SecCap)     |                                    |
 |   [5GSM: PDU Session Est Req]     |                                    |
 |         (PSI=1, DNN, S-NSSAI)     |                                    |
 |                                   |===== 2. Nsmf_PDUSession_Create ===>|
 |                                   |<==== 3. Response (IP, QoS, QFI) ===|
 |                                   |                                    |
 |<==== 4. Registration Accept ======|                                    |
 |   (5GMM: 5G-GUTI, T3512, NSSAI)   |                                    |
 |   [5GSM: PDU Session Est Accept]  |                                    |
 |         (IPv4=10.45.0.2, QFI=1)   |                                    |
 |                                   |                                    |
 |===== 5. Registration Complete ===>|                                    |
 |   [5GSM: PDU Session Est Complete]|                                    |
```

### Flow Breakdown

1. **Registration Request (UE → AMF)**:
   - Contains subscriber's concealed identity (**SUCI**), registration type (`Initial Registration`), security capabilities, and requested network slice (**S-NSSAI**).
   - Piggybacks 5GSM **PDU Session Establishment Request** requesting a PDU session for Data Network Name (DNN) `internet`.
2. **Session Creation (AMF ↔ SMF)**:
   - AMF forwards session context to the SMF over Service Based Interfaces (SBI).
3. **Registration Accept (AMF → UE)**:
   - Allocates **5G-GUTI** (`5G-TMSI 0x5678ABCD`), periodic registration timer **T3512** (`54 min`), and **Allowed NSSAI**.
   - Embeds 5GSM **PDU Session Establishment Accept** providing IPv4 address `10.45.0.2`, QoS Flow Identifier `QFI=1` (5QI `9`), and authorized QoS rules.
4. **Registration Complete (UE → AMF)**:
   - Confirms successful allocation and session activation.

---

## 3. Project Implementation

### Header & Source Files

| File | Description |
|------|-------------|
| `include/3gpp/nr_nas/NrNasCommon.hpp` | Enums: `ExtendedProtocolDiscriminator` (`GMM=0x7E`, `GSM=0x2E`), `SecurityHeaderType`, `GmmMessageType`, `GsmMessageType`; `NrNasHeader` & `NrGsmHeader` |
| `include/3gpp/nr_nas/NrNasIe.hpp` | Information Elements: `Suci`, `NrGuti`, `SNssai` (SST+SD), `Dnn`, `NrPduAddress`, `NrQosRule` |
| `include/3gpp/nr_nas/GmmMessage.hpp` | 5GMM messages: `RegistrationRequest`, `RegistrationAccept`, `RegistrationComplete` |
| `include/3gpp/nr_nas/GsmMessage.hpp` | 5GSM messages: `PduSessionEstablishmentRequest`, `PduSessionEstablishmentAccept`, `PduSessionEstablishmentReject` |
| `src/nr_nas/NrNasCommon.cpp` | 3-octet 5GMM header and 4-octet 5GSM header encoders/decoders |
| `src/nr_nas/NrNasIe.cpp` | SUCI null-scheme encoder, 5G-GUTI TLV, S-NSSAI 24-bit SD formatting |
| `src/nr_nas/GmmMessage.cpp` | 5GMM message serialization and embedded 5GSM container processing |
| `src/nr_nas/GsmMessage.cpp` | 5GSM message serialization, QoS rules, and PDU address formatting |

### Demo Application — `apps/demo_08_5g_registration.cpp`

Simulates an end-to-end UE ↔ AMF 5G Registration and PDU Session setup over UDP loopback sockets:
- UE encodes SUCI, S-NSSAI, and piggybacked PDU Session Request
- AMF decodes SUCI, generates 5G-GUTI, allocates IP `10.45.0.2`, and replies with Registration Accept
- UE acknowledges with Registration Complete
- All 3 messages captured into `output_08_5g_registration.pcap` with full Ethernet/IP/UDP headers

---

## 4. How to Run the Tests & Inspect Output

### Build the Project
```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
```

### Run Unit Tests (Lesson 08 only)
```bash
./build/tests/unit_tests --gtest_filter="*NrNas*:*Gmm*:*Gsm*"
```

### Run Standalone Demo
```bash
./build/apps/demo_08_5g_registration
```

### Inspect Output in tcpdump / Wireshark
```bash
tcpdump -r output_08_5g_registration.pcap -nv
```

Or view with detailed hex output:
```bash
tshark -r output_08_5g_registration.pcap -x
```

---

## 5. Key Engineering Concepts

### 1. SUCI & Subscriber Privacy (TS 33.501, TS 24.501)
In 2G/3G/4G, IMSI catching was a fundamental vulnerability. In 5G:
$$\text{SUCI} = \text{Type}(001) + \text{PLMN} + \text{Routing Indicator} + \text{Protection Scheme} + \text{Home PKI} + \text{Scheme Output}$$
When using the **Null Scheme** (`Profile 0`), the MSIN digits are BCD encoded without encryption (used in private networks and test benches). In commercial deployments, ECIES Profile A (Curve25519) or Profile B (secp256r1) encrypts the MSIN with the Home Network's public key.

### 2. Network Slicing (S-NSSAI)
A Single Network Slice Selection Assistance Information (S-NSSAI) identifies an isolated end-to-end logical network:
- **SST (Slice/Service Type, 8 bits)**:
  - `1` = eMBB (Enhanced Mobile Broadband)
  - `2` = URLLC (Ultra-Reliable Low-Latency Communication)
  - `3` = MIoT (Massive Internet of Things)
  - `4` = V2X (Vehicle-to-Everything)
- **SD (Slice Differentiator, 24 bits)**: Optional discriminator distinguishing multiple slices with the same SST (e.g. `0x000001`).

### 3. 5G-GUTI Structure
Allocated by the AMF to conceal the subscriber identity after registration:
$$\text{5G-GUTI} = \text{MCC} + \text{MNC} + \text{AMF Region ID} + \text{AMF Set ID} + \text{AMF Pointer} + \text{5G-TMSI}$$
- **GUAMI**: Globally Unique AMF Identifier (`PLMN + AMFI`)
- **5G-S-TMSI**: `AMF Set ID + AMF Pointer + 5G-TMSI` (48 bits, optimized for radio paging)

### 4. QoS Flows & QFI
5G replaces EPS Bearers with **QoS Flows**. Each QoS flow is identified by a **QFI** (QoS Flow Identifier, 1 to 64) and configured with a **5QI** (5G QoS Identifier):
- `5QI 9`: Default best-effort Internet traffic (Delay 300 ms, Packet Error Rate $10^{-6}$)
- `5QI 1`: Conversational Voice (VoNR, Delay 100 ms, Guaranteed Flow Bit Rate)

---

## 6. Wireshark Analysis

Opening `output_08_5g_registration.pcap` reveals the 3-step exchange:

```
Frame 1: 127.0.0.1 → 127.0.0.3   UDP  Len=58   UE → AMF 5GMM Registration Request
Frame 2: 127.0.0.3 → 127.0.0.1   UDP  Len=63   AMF → UE 5GMM Registration Accept
Frame 3: 127.0.0.1 → 127.0.0.3   UDP  Len=5    UE → AMF 5GMM Registration Complete
```

Inspecting the payload of **Frame 1**:
- Bytes `7e 00 41`: Extended Protocol Discriminator = `0x7E` (5GMM), Security Header = Plain NAS (`0x00`), Message Type = Registration Request (`0x41`)
- Byte `71`: ngKSI = `7` (no key), Registration Type = `1` (Initial Registration)
- Bytes `00 0d 01 00 f1 10 00 00 00 00 10 32 54 76 98`: SUCI with 2-byte length `13`, type `1`, PLMN `001-01`, routing indicator `0000`, null scheme, MSIN `0123456789`
- Bytes `02 80 20`: UE Security Capability
- Bytes `01 04 01 00 00 01`: Requested NSSAI (SST `1`, SD `0x000001`)
- Bytes `00 14 2e 01 01 c1 11 04 01 00 00 01 09 08 69 6e 74 65 72 6e 65 74`: Piggybacked 5GSM PDU Session Establishment Request (`EPD=0x2E, PSI=1, PTI=1, MT=0xC1`) for DNN `internet`

Inspecting **Frame 2**:
- Bytes `7e 00 42 01`: Registration Accept with 3GPP access result
- Bytes `77 0b f2 00 f1 10 01 00 41 56 78 ab cd`: 5G-GUTI TLV (`IEI=0x77`, TMSI `0x5678ABCD`)
- Embedded 5GSM Accept providing PDU address `10.45.0.2` and QoS rule `QFI=1, 5QI=9`.

---

## 7. Test Cases (`test_08_nr_nas.cpp`)

| Test Name | Description |
|-----------|-------------|
| `NrNasTest.GmmHeaderEncodeDecode` | Validates 3-octet 5GMM header encoding and field extraction |
| `NrNasTest.GsmHeaderEncodeDecode` | Validates 4-octet 5GSM header encoding with PSI and PTI |
| `NrNasTest.SuciEncodingDecoding` | Validates SUCI Null-scheme packing with PLMN and MSIN |
| `NrNasTest.NrGutiEncodingDecoding` | Validates 5G-GUTI TLV with AMF Region, Set ID, Pointer, and 5G-TMSI |
| `NrNasTest.SNssaiEncodingDecoding` | Validates S-NSSAI formatting both with and without 24-bit SD |
| `GmmTest.RegistrationRequestRoundTrip` | Round-trip validation of Registration Request with embedded 5GSM PDU |
| `GmmTest.RegistrationAcceptRoundTrip` | Round-trip validation of Registration Accept with 5G-GUTI and Allowed NSSAI |
| `GsmTest.PduSessionEstablishmentRequestRoundTrip` | Round-trip validation of 5GSM PDU Session Establishment Request |
| `GsmTest.PduSessionEstablishmentAcceptRoundTrip` | Round-trip validation of 5GSM Accept with QoS rule and PDU address |
| `GsmTest.PduSessionEstablishmentReject` | Validates 5GSM rejection with standard cause code |
| `NrNasIntegrationTest.UeAmfLoopbackRegistration` | Integration test simulating complete 3-message UE ↔ AMF Registration flow |

---

## 8. References

| Specification | Title |
|---------------|-------|
| **3GPP TS 23.501** | System Architecture for the 5G System (5GS) |
| **3GPP TS 23.502** | Procedures for the 5G System (5GS Registration & PDU Session Flows) |
| **3GPP TS 24.501** | Non-Access-Stratum (NAS) protocol for 5G System (5GS); Stage 3 (5GMM & 5GSM) |
| **3GPP TS 33.501** | Security architecture and procedures for 5G System (SUCI, ECIES, 5G-AKA) |
