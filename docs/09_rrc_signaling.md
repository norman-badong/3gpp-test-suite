# Lesson 09: LTE & 5G NR RRC Signaling — ASN.1 Aligned Packed Encoding Rules (APER)

## Overview

In 4G LTE (E-UTRA) and 5G NR, **Radio Resource Control (RRC)** is the Layer 3 control-plane protocol that runs between the User Equipment (UE) and the radio base station (eNodeB / gNodeB) over the **Uu radio interface** (TS 36.331, TS 38.331).

RRC is responsible for:
1. **Connection Management**: State transitions between `RRC_IDLE`, `RRC_INACTIVE`, and `RRC_CONNECTED`.
2. **Signaling Radio Bearers (SRB)**: Configuring SRB0 (CCCH), SRB1 (DCCH, initial NAS & RRC), and SRB2 (DCCH, lower priority NAS).
3. **Data Radio Bearers (DRB)**: Establishing user-plane radio bearers for subscriber traffic.
4. **Security & Configuration**: Radio link configuration, measurement reporting, handovers, and dual connectivity.
5. **NAS Message Transport**: Encapsulating initial NAS PDUs (EMM Attach Request / 5GMM Registration Request) inside `RRCSetupComplete`.

Unlike NAS, which uses Type-Length-Value (TLV/LV) formats, 3GPP RRC specifications are written in **ASN.1 (Abstract Syntax Notation One)** and encoded using **APER (Aligned Packed Encoding Rules, ITU-T X.691)** to minimize over-the-air bit consumption.

---

### 3GPP Context

| Channel / Interface | Between | Role & Purpose |
|---------------------|---------|----------------|
| **Uu (RRC)** | UE ↔ gNodeB / eNodeB | Radio connection setup, bearer establishment, mobility (TS 38.331 / TS 36.331) |
| **SRB0 (CCCH)** | UE ↔ gNB (RLC-TM) | Common Control Channel carrying `RRCSetupRequest` & `RRCSetup` |
| **SRB1 (DCCH)** | UE ↔ gNB (RLC-AM) | Dedicated Control Channel carrying `RRCSetupComplete` & `RRCReconfiguration` |
| **DRB1 (DTCH)** | UE ↔ gNB (RLC-AM/UM) | Dedicated Traffic Channel carrying subscriber IP traffic |
| **S1AP / NG-AP** | gNodeB ↔ MME / AMF | Core network signaling carrying forwarded Initial UE Messages (TS 38.413) |

---

## 1. Protocol Structure

### ASN.1 APER Encoding Model (ITU-T X.691)

Unlike basic binary formats, APER packs values at the **bit level** based on their predefined schema constraints:

```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
|Chc|    39-bit UE Identity     | ...
+---+---+---+---+---+---+---+---+
|Cause |Sp | (padded to byte boundary)
+---+---+---+---+---+---+---+---+
```

| ASN.1 Type | APER Encoding Rule |
|------------|---------------------|
| **BOOLEAN** | 1 bit (`1` = true, `0` = false) |
| **INTEGER (min..max)** | Range $R = \text{max} - \text{min} + 1$. If $R \le 255$, encoded in $\lceil \log_2 R \rceil$ unaligned bits. If $R = 256$, aligned to byte and encoded in 1 octet. If $R \le 65536$, aligned to byte and encoded in 2 octets. |
| **ENUMERATED** | Extension bit (`0` = root) followed by constrained integer $0 \dots (N-1)$ |
| **CHOICE** | Extension bit (`0` = root) followed by choice alternative index |
| **BIT STRING (SIZE (N))** | Fixed $N$ bits written sequentially |
| **OCTET STRING** | Byte-aligned length determinant (1 octet for length $< 128$) followed by octet sequence |

---

## 2. 3GPP Protocol Flow

### 5G NR / LTE RRC Connection Establishment Flow (TS 38.331 §5.3.3)

```
UE                                                  gNodeB
 |                                                    |
 |===== 1. RRCSetupRequest (SRB0, UL-CCCH) ==========>|
 |   (Choice: 39-bit 5G-S-TMSI, mo-Signalling)        |
 |                                                    |
 |<==== 2. RRCSetup (SRB0, DL-CCCH) ==================|
 |   (SRB1 config, RLC-AM mode, MasterCellGroup)      |
 |                                                    |
 |===== 3. RRCSetupComplete (SRB1, UL-DCCH) =========>|
 |   (Selected PLMN, Dedicated NAS: RegistrationReq)  |
 |                                                    |
 |<==== 4. RRCReconfiguration (SRB1, DL-DCCH) ========|
 |   (DRB1 activation, QFI=1, SecondaryCellGroup)     |
 |                                                    |
 |===== 5. RRCReconfigurationComplete (SRB1) ========>|
 |                                                    |
```

### Flow Breakdown

1. **RRCSetupRequest (UE → gNodeB, UL-CCCH)**:
   - Sent on SRB0 using Transparent Mode (RLC-TM).
   - Carries UE initial identity (39-bit `5G-S-TMSI` or random value) and establishment cause (`mo-Signalling`).
2. **RRCSetup (gNodeB → UE, DL-CCCH)**:
   - Configures Signaling Radio Bearer 1 (**SRB1**) in Acknowledged Mode (RLC-AM) and applies Master Cell Group (MCG) configuration.
   - UE transitions from `RRC_IDLE` to `RRC_CONNECTED`.
3. **RRCSetupComplete (UE → gNodeB, SRB1, UL-DCCH)**:
   - Confirms SRB1 setup, indicates selected PLMN ID, and embeds the initial NAS message (`RegistrationRequest` from Lesson 08 or `AttachRequest` from Lesson 07).
4. **RRCReconfiguration (gNodeB → UE, SRB1, DL-DCCH)**:
   - Establishes user-plane Data Radio Bearer 1 (**DRB1**) mapped to QoS Flow `QFI=1`.
5. **RRCReconfigurationComplete (UE → gNodeB, SRB1, UL-DCCH)**:
   - Confirms user-plane data path readiness.

---

## 3. Project Implementation

### Header & Source Files

| File | Description |
|------|-------------|
| `include/3gpp/rrc/Asn1Aper.hpp` | ASN.1 APER bit-level encoder (`AperWriter`) and decoder (`AperReader`) |
| `include/3gpp/rrc/RrcTypes.hpp` | Enums: `EstablishmentCause`, `InitialUeIdentityType`, `RlcMode`, `PduChannelType` |
| `include/3gpp/rrc/RrcMessage.hpp` | RRC PDUs: `RrcSetupRequest`, `RrcSetup`, `RrcSetupComplete`, `RrcReconfiguration`, `RrcReconfigurationComplete` |
| `src/rrc/Asn1Aper.cpp` | APER bit packing, constrained integer range calculation, and octet alignment |
| `src/rrc/RrcMessage.cpp` | APER serialization and deserialization for all 5 RRC procedure messages |

### Demo Application — `apps/demo_09_rrc_signaling.cpp`

Simulates an end-to-end UE ↔ gNodeB 5-step RRC signaling exchange over UDP loopback sockets:
- UE transmits APER-encoded `RrcSetupRequest` with 39-bit identity
- gNodeB configures SRB1 via `RrcSetup`
- UE establishes SRB1 and replies with `RrcSetupComplete` carrying embedded 5G NAS PDU
- gNodeB activates DRB1 via `RrcReconfiguration`
- UE acknowledges with `RrcReconfigurationComplete`
- All 5 packets captured to `output_09_rrc.pcap` with full Ethernet/IP/UDP headers

---

## 4. How to Run the Tests & Inspect Output

### Build the Project
```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
```

### Run Unit Tests (Lesson 09 only)
```bash
./build/tests/unit_tests --gtest_filter="*Aper*:*Rrc*"
```

### Run Standalone Demo
```bash
./build/apps/demo_09_rrc_signaling
```

### Inspect Output in tcpdump / Wireshark
```bash
tcpdump -r output_09_rrc.pcap -nv
```

Or view with detailed hex output:
```bash
tshark -r output_09_rrc.pcap -x
```

---

## 5. Key Engineering Concepts

### 1. Bit-Level Packing Efficiency
In traditional binary protocols (e.g. Diameter or IP), an establishment cause field would consume at least 1 full octet (8 bits). In APER:
- 8 enumerated values require only 3 bits: $\lceil \log_2 8 \rceil = 3$.
- A 39-bit identity and 3-bit cause fit into just 6 octets total without byte-alignment overhead until the message completes.

### 2. Transparent vs Acknowledged RLC Modes
- **RLC-TM (Transparent Mode)**: Used for `RrcSetupRequest` and `RrcSetup` over SRB0. Zero header overhead; segments are sent directly across the physical layer.
- **RLC-AM (Acknowledged Mode)**: Used for SRB1/SRB2 and DRBs. Provides guaranteed in-order delivery, ARQ retransmission, and segmentation.

### 3. Dedicated NAS Transport
In both LTE and 5G NR, the radio layer does not parse the subscriber's NAS signaling. Instead, `RrcSetupComplete` encapsulates the raw NAS PDU into the `DedicatedNAS-Message` octet string, which the gNodeB forwards unchanged to the AMF over NG-AP `InitialUEMessage`.

---

## 6. Wireshark Analysis

Opening `output_09_rrc.pcap` displays the 5-message exchange:

```
Frame 1: 127.0.0.1 → 127.0.0.10  UDP  Len=6    UE → gNodeB RRCSetupRequest (UL-CCCH)
Frame 2: 127.0.0.10 → 127.0.0.1  UDP  Len=6    gNodeB → UE RRCSetup (DL-CCCH)
Frame 3: 127.0.0.1 → 127.0.0.10  UDP  Len=12   UE → gNodeB RRCSetupComplete (UL-DCCH)
Frame 4: 127.0.0.10 → 127.0.0.1  UDP  Len=6    gNodeB → UE RRCReconfiguration (DL-DCCH)
Frame 5: 127.0.0.1 → 127.0.0.10  UDP  Len=1    UE → gNodeB RRCReconfigurationComplete
```

Inspecting the payload of **Frame 1**:
- Payload bytes: `45 67 89 ab cd 60`
  - Bit 0: Choice alternative `0` (`5G-S-TMSI-Part1`)
  - Bits 1–39: 39-bit UE identity (`0x456789ABCD`)
  - Bits 40–42: Establishment Cause = `3` (`mo-Signalling`)
  - Bit 43: Spare bit `0`
  - Bits 44–47: Zero padding to byte boundary

Inspecting **Frame 3**:
- Payload contains `RrcSetupComplete`:
  - Transaction ID `0`
  - Selected PLMN `1`
  - Embedded 5GS Registration NAS PDU: `7e 00 41 71 ...`

---

## 7. Test Cases (`test_09_rrc.cpp`)

| Test Name | Description |
|-----------|-------------|
| `AperPrimitivesTest.BooleanAndConstrainedInt` | Validates bit-level booleans and constrained integers with APER range rules |
| `AperPrimitivesTest.EnumeratedAndChoice` | Validates enumerated and choice index bit-packing |
| `AperPrimitivesTest.BitString39Bits` | Validates 39-bit bit string serialization and deserialization |
| `AperPrimitivesTest.OctetStringShortAndLong` | Validates short and multi-octet APER octet string length determinants |
| `RrcMessageTest.RrcSetupRequestRoundTrip` | Round-trip validation of `RrcSetupRequest` with 39-bit identity and cause |
| `RrcMessageTest.RrcSetupRoundTrip` | Round-trip validation of `RrcSetup` with SRB1 and MasterCellGroup |
| `RrcMessageTest.RrcSetupCompleteWithNasPdu` | Validates `RrcSetupComplete` carrying embedded 5GS Registration NAS PDU |
| `RrcMessageTest.RrcReconfigurationRoundTrip` | Validates `RrcReconfiguration` with DRB1 and QoS Flow ID |
| `RrcMessageTest.RrcReconfigurationCompleteRoundTrip` | Validates `RrcReconfigurationComplete` transaction ID confirmation |
| `RrcIntegrationTest.FullRadioHandshakeUeGnb` | Integration test simulating the complete 5-way UE ↔ gNodeB RRC procedure |

---

## 8. References

| Specification | Title |
|---------------|-------|
| **3GPP TS 38.331** | NR; Radio Resource Control (RRC) protocol specification (5G NR RRC) |
| **3GPP TS 36.331** | E-UTRA; Radio Resource Control (RRC) protocol specification (LTE RRC) |
| **ITU-T X.691** | Information technology – ASN.1 encoding rules: Specification of Packed Encoding Rules (PER) |
| **3GPP TS 38.300** | NR; NR and NG-RAN Overall Description; Stage-2 |
