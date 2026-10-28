# Lesson 07: LTE Attach — Non-Access Stratum (NAS EMM & ESM Procedures)

## Overview

In 4G LTE, the **Non-Access Stratum (NAS)** protocol stack runs directly between the User Equipment (UE) and the Mobility Management Entity (MME) in the Evolved Packet Core (EPC). NAS operates transparently through the eNodeB radio base station across the **S1-MME** interface.

NAS is divided into two distinct sub-layers:
1. **EPS Mobility Management (EMM)**: Manages UE registration, location tracking, identity confidentiality, authentication, and security contexts (TS 24.301).
2. **EPS Session Management (ESM)**: Manages end-to-end user-plane IP connectivity, establishing and releasing EPS Default and Dedicated Bearers with assigned IP addresses and QoS classes (QCI).

During an **Initial Attach**, 3GPP TS 23.401 optimizes radio resources by **piggybacking** the ESM message (`PDN Connectivity Request`) inside an Information Element of the EMM message (`Attach Request`).

---

### 3GPP Context

| Interface / Layer | Between | Role & Purpose |
|-------------------|---------|----------------|
| **NAS EMM** | UE ↔ MME | Attach, Detach, Tracking Area Update (TAU), Service Request, Security Mode Control |
| **NAS ESM** | UE ↔ MME | PDN Connectivity, Default Bearer Activation, Bearer Resource Allocation |
| **S1AP** | eNodeB ↔ MME | Radio Network Layer transport encapsulating NAS PDUs (TS 36.413) |
| **S1-U** | eNodeB ↔ S-GW | GTP-U user-plane tunnel carrying subscriber IP traffic (TS 29.281) |
| **S6a** | MME ↔ HSS | Diameter authentication vectors & subscription data (TS 29.272, Lesson 06) |

---

## 1. Protocol Structure

### Plain NAS EMM Header (TS 24.301 §9.8) — 2 bytes

```
  0                   1
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Sec Hdr Type | Prot Discrim  |  Message Type  |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| **Security Header Type** | 4 bits | `0x0` = Plain NAS (not security protected), `0x1` = Integrity protected, `0x2` = Ciphered |
| **Protocol Discriminator** | 4 bits | `0x07` = EPS Mobility Management (EMM), `0x02` = EPS Session Management (ESM) |
| **Message Type** | 8 bits | Identifies the EMM procedure (e.g., `0x41` = Attach Request, `0x42` = Attach Accept) |

### NAS ESM Header (TS 24.301 §9.9) — 3 bytes

```
  0                   1                   2
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  EPS Bearer ID | Prot Discrim  |   Proc Trans ID |  Message Type  |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| **EPS Bearer Identity (EBI)** | 4 bits | `0` in requests before assignment; `5`–`15` assigned for active EPS bearers |
| **Protocol Discriminator** | 4 bits | `0x02` = EPS Session Management (ESM) |
| **Procedure Transaction Identity (PTI)** | 8 bits | Correlates ESM requests with responses (e.g. `1`) |
| **Message Type** | 8 bits | `0xD0` = PDN Connectivity Request, `0xC1` = Activate Default Bearer Context Request |

---

## 2. 3GPP Protocol Flow

### LTE Initial Attach Sequence (TS 23.401 §5.3.2.1)

```
UE                                MME                                HSS
 |                                 |                                  |
 |===== 1. Attach Request ========>|                                  |
 |   (EMM: IMSI, Attach Type)      |                                  |
 |   [ESM: PDN Connectivity Req]   |                                  |
 |                                 |===== 2. S6a AIR (Lesson 06) ====>|
 |                                 |<==== 3. S6a AIA (Vectors) =======|
 |                                 |                                  |
 |<==== 4. Attach Accept ==========|                                  |
 |   (EMM: GUTI, TAI List, T3412)  |                                  |
 |   [ESM: Activate Default Bearer]|                                  |
 |         (IPv4, APN, QCI=9)      |                                  |
 |                                 |                                  |
 |===== 5. Attach Complete =======>|                                  |
 |   [ESM: Activate Bearer Accept] |                                  |
 |                                 |                                  |
```

### Flow Breakdown

1. **Attach Request (UE → MME)**:
   - Contains subscriber identity (IMSI `001010123456789`), EPS Attach Type (`0x01`), and UE Network Capabilities.
   - Embeds ESM **PDN Connectivity Request** requesting initial IPv4 user-plane connectivity.
2. **Authentication (MME ↔ HSS)**:
   - Covered in Lesson 06 via Diameter S6a AIR/AIA exchange to fetch E-UTRAN authentication vectors.
3. **Attach Accept (MME → UE)**:
   - Confirms registration, allocates a **GUTI** (`M-TMSI 0xABCD1234`), sets the periodic TAU timer **T3412** (`54 min`), and assigns a **TAI List**.
   - Embeds ESM **Activate Default EPS Bearer Context Request** allocating EPS Bearer ID `5`, IPv4 address `10.45.0.1`, APN `internet`, and QCI `9` (default best-effort Internet QoS).
4. **Attach Complete (UE → MME)**:
   - Confirms bearer establishment with embedded ESM **Activate Default EPS Bearer Context Accept**.

---

## 3. Project Implementation

### Header & Source Files

| File | Description |
|------|-------------|
| `include/3gpp/lte_nas/NasCommon.hpp` | Enums: `ProtocolDiscriminator`, `SecurityHeaderType`, `EmmMessageType`, `EsmMessageType`; `NasHeader` and `EsmHeader` structures |
| `include/3gpp/lte_nas/NasIe.hpp` | Information Elements: `MobileIdentity` (IMSI packed BCD), `Guti`, `TaiList`, `EpsQoS`, `AccessPointName`, `PdnAddress` |
| `include/3gpp/lte_nas/EmmMessage.hpp` | EMM messages: `AttachRequest`, `AttachAccept`, `AttachComplete` |
| `include/3gpp/lte_nas/EsmMessage.hpp` | ESM messages: `PdnConnectivityRequest`, `ActivateDefaultEpsBearerContextRequest`, `ActivateDefaultEpsBearerContextAccept` |
| `src/lte_nas/NasCommon.cpp` | NAS & ESM header encoders and decoders |
| `src/lte_nas/NasIe.cpp` | BCD IMSI packer/unpacker, PLMN 3-octet format, GUTI and TAI list encoders |
| `src/lte_nas/EmmMessage.cpp` | EMM message serialization and nested ESM container handling |
| `src/lte_nas/EsmMessage.cpp` | ESM message serialization and bearer parameter parsing |

### Demo Application — `apps/demo_07_lte_nas.cpp`

Simulates an end-to-end UE ↔ MME Attach procedure over UDP loopback sockets:
- UE encodes and transmits **Attach Request** with piggybacked **PDN Connectivity Request**
- MME decodes IMSI and ESM container, allocates GUTI and IP address, and replies with **Attach Accept** + **Activate Default Bearer Request**
- UE decodes allocated IP `10.45.0.1` and confirms with **Attach Complete**
- All 3 messages written to `output_07_lte_nas.pcap` with full Ethernet/IP/UDP headers

---

## 4. How to Run the Tests & Inspect Output

### Build the Project
```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
```

### Run Unit Tests (Lesson 07 only)
```bash
./build/tests/unit_tests --gtest_filter="*Nas*:*Emm*:*Esm*"
```

### Run Standalone Demo
```bash
./build/apps/demo_07_lte_nas
```

### Inspect Output in tcpdump / Wireshark
```bash
tcpdump -r output_07_lte_nas.pcap -nv
```

Or view with detailed hex output:
```bash
tshark -r output_07_lte_nas.pcap -x
```

---

## 5. Key Engineering Concepts

### 1. IMSI Packed BCD Encoding (TS 24.008 §10.5.1.4)
IMSI digits are stored in binary coded decimal (BCD) with swapped nibbles:
- Octet 1: Identity digit 1 in bits 8–5, Odd/Even indicator in bit 4 (`1` = odd), Type of Identity in bits 3–1 (`001` = IMSI).
- Subsequent Octets: Low nibble stores digit $2n$, high nibble stores digit $2n+1$.
- If the IMSI length is even, the unused high nibble of the final octet is filled with `0xF`.

### 2. Globally Unique Temporary UE Identity (GUTI)
To protect subscriber privacy over the radio interface after Initial Attach:
$$\text{GUTI} = \text{MCC} + \text{MNC} + \text{MMEGI} + \text{MMEC} + \text{M-TMSI}$$
- **MME Identifier (MMEI)**: MME Group ID (16 bits) + MME Code (8 bits)
- **M-TMSI**: 32-bit random temporary identity assigned to the UE by the MME

### 3. Tracking Area Identity (TAI) & TAI List
A Tracking Area Identity consists of PLMN (`MCC + MNC`) and a 16-bit Tracking Area Code (`TAC`). The MME provides a list of allowed TAIs so the UE does not trigger unnecessary Tracking Area Updates while moving between adjacent cells.

### 4. ESM Message Piggybacking
LTE does not require separate signaling transactions for EPS bearer setup during attach. The ESM message bytes are encapsulated directly in the `ESM message container` Information Element of EMM messages, reducing initial connection latency and radio overhead.

---

## 6. Wireshark Analysis

Opening `output_07_lte_nas.pcap` displays the 3-step exchange:

```
Frame 1: 127.0.0.1 → 127.0.0.2   UDP  Len=23   UE → MME Attach Request
Frame 2: 127.0.0.2 → 127.0.0.1   UDP  Len=47   MME → UE Attach Accept
Frame 3: 127.0.0.1 → 127.0.0.2   UDP  Len=7    UE → MME Attach Complete
```

Inspecting the payload of **Frame 1**:
- Bytes `07 41`: Security Header = Plain NAS (`0x0`), Protocol Discriminator = EMM (`0x7`), Message Type = Attach Request (`0x41`)
- Byte `71`: NAS key set identifier = `7` (no key), Attach type = `1` (EPS attach)
- Bytes `08 09 10 10 10 32 54 76 98`: Mobile Identity LV containing IMSI `001010123456789`
- Bytes `04 e0 00 00 00`: UE network capability LV
- Bytes `00 04 02 01 d0 11`: ESM container (length=4) with ESM header (`EBI=0, PD=2, PTI=1, MT=0xD0`) and PDN Type (`IPv4`)

Inspecting **Frame 2**:
- Bytes `07 42`: Attach Accept
- Contains TAI list, embedded Default Bearer setup (`QCI=9, APN='internet', IPv4=10.45.0.1`), and GUTI TLV (`IEI=0x50`).

---

## 7. Test Cases (`test_07_lte_nas.cpp`)

| Test Name | Description |
|-----------|-------------|
| `NasTest.HeaderEncodeDecode` | Validates NAS plain header serialization and field decoding |
| `NasTest.ImsiMobileIdentityEncoding` | Validates packed BCD encoding for 15-digit IMSI `001010123456789` |
| `NasTest.GutiEncoding` | Validates GUTI TLV encoding with PLMN, MMEGI, MMEC, and M-TMSI |
| `NasTest.TaiListEncoding` | Validates TAI list LV structure with PLMN and TAC list |
| `EmmTest.AttachRequestRoundTrip` | Round-trip validation of full Attach Request with embedded ESM |
| `EmmTest.AttachAcceptRoundTrip` | Round-trip validation of Attach Accept with GUTI, TAI, and default bearer |
| `EsmTest.PdnConnectivityRequestRoundTrip` | Round-trip validation of ESM PDN Connectivity Request |
| `EsmTest.ActivateDefaultBearerRoundTrip` | Round-trip validation of ESM Default Bearer activation request |
| `NasIntegrationTest.UeMmeLoopbackAttach` | Integration test simulating complete 3-message UE ↔ MME Attach flow |

---

## 8. References

| Specification | Title |
|---------------|-------|
| **3GPP TS 23.401** | General Packet Radio Service (GPRS) enhancements for E-UTRAN access (Architecture & Attach Flow) |
| **3GPP TS 24.301** | Non-Access-Stratum (NAS) protocol for Evolved Packet System (EPS); Core network aspects (EMM/ESM) |
| **3GPP TS 24.008** | Mobile radio interface Layer 3 specification; Core network protocols (IMSI & Mobile Identity formats) |
| **3GPP TS 33.401** | 3GPP System Architecture Evolution (SAE); Security architecture |
