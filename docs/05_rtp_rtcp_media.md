# Lesson 05: RTP & RTCP (Real-time Transport & Control Protocol)

## Overview

**RTP (Real-time Transport Protocol)** is the standard protocol for transporting real-time audio and video over IP networks. In 4G VoLTE and 5G VoNR, after SIP (Lesson 04) negotiates the call using SDP (Lesson 03), the actual voice audio is streamed packet-by-packet using RTP. **RTCP (RTP Control Protocol)** runs alongside RTP on an adjacent port to deliver quality statistics and session metadata.

This lesson covers:
- **RFC 3550**: RTP header framing, SSRC, sequence numbers, timestamps, RTCP SR/RR/SDES
- **RFC 3551**: RTP Audio/Video Profile — payload type assignments
- **3GPP TS 26.114**: Media handling for IMS Multimedia Telephony (AMR-WB, EVS, jitter buffer)
- **Jitter estimation**: RFC 3550 Appendix A.8 interarrival jitter filter (low-pass EWMA)

### 3GPP Context

| Interface | Between | RTP Role |
|-----------|---------|---------|
| **Mb (IMS)** | UE ↔ UE (via P-CSCF) | VoLTE / VoNR AMR-WB or EVS voice stream |
| **Mr (IMS)** | AS (MRFC) ↔ MRF | Media Resource Function — conferencing, IVR |
| **VoWiFi (ePDG)** | UE ↔ ePDG | RTP over IPSec for Wi-Fi Calling |
| **WebRTC / IMS** | Browser ↔ IMS | SRTP (encrypted RTP) for web voice/video |

---

## 1. Protocol Structure

### RTP Header (RFC 3550 §5.1) — 12 bytes minimum

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |V=2|P|X|  CC   |M|     PT      |       Sequence Number         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                           Timestamp                           |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           Synchronization Source (SSRC) Identifier           |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |            Contributing Source (CSRC) [0..15 × 4 bytes]      |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Bits | 3GPP VoLTE/VoNR Significance |
|-------|------|-------------------------------|
| **V** | 2 | Always `2` (RTP version) |
| **P** | 1 | Padding flag |
| **X** | 1 | Extension header present |
| **CC** | 4 | CSRC count (usually 0 for point-to-point) |
| **M** | 1 | Marker — `1` on first packet of a talkspurt after silence |
| **PT** | 7 | Payload type — negotiated in SDP (e.g. `104`=AMR-WB, `108`=EVS) |
| **Seq** | 16 | Increments by 1 per packet; detects loss and reordering |
| **Timestamp** | 32 | Sampling clock ticks — AMR-WB: +320 per 20ms frame |
| **SSRC** | 32 | Unique random 32-bit stream source identifier |

### RTCP Compound Packet Structure (RFC 3550 §6)

```
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | V |P| RC/SC |   Packet Type  |            Length              |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         SSRC of sender                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  [SR-specific: NTP timestamp, RTP timestamp, packet count...] |
 |  [RR-specific: Report Blocks per active stream]               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| RTCP Type | PT | Purpose |
|-----------|-----|---------|
| `SR` (Sender Report) | 200 | Sender stats: NTP wall time, RTP timestamp, packet/byte counts |
| `RR` (Receiver Report) | 201 | Receiver stats: fraction lost, cumulative lost, jitter, last SR |
| `SDES` (Source Description) | 202 | CNAME, NAME, EMAIL, PHONE — identifies stream source |
| `BYE` | 203 | Stream termination notification |

---

## 2. 3GPP Protocol Flow

### VoLTE RTP / RTCP Exchange

```
    Caller (UE1)                                    Callee (UE2)
         |                                               |
         | ======== RTP Stream (UDP port 49170) =======> |
         |   [AMR-WB frames, PT=104, 16kHz, 20ms]        |
         |   Seq: 1001, TS: 3200                         |
         |   Seq: 1002, TS: 3520                         |
         |   ...                                         |
         |   Seq: 1013, TS: 7360  (13 packets)           |
         |                                               |
         | ------- RTCP SR (UDP port 49171) -----------> |
         |   NTP=1700000000, RTP TS=3200                 |
         |   Packets Sent=13, Octets Sent=1690           |
         |                                               |
         | <------ RTCP RR (UDP port 49171) ------------ |
         |   Fraction Lost=0, Cumulative Lost=0          |
         |   Interarrival Jitter=11.5ms                  |
         |                                               |
         | ======== RTP Stream continues... ==========> |
```

### VoLTE Clock & Timing

$$\text{AMR-WB Clock Rate} = 16{,}000 \text{ Hz}$$
$$\text{Ticks per 20ms Frame} = 16{,}000 \times 0.020 = 320 \text{ timestamp ticks}$$

---

## 3. Project Implementation

### Source Files

| File | Description |
|------|-------------|
| `include/3gpp/rtp/RtpPacket.hpp` | 12-byte RTP header, CSRC list, AMR-WB factory (PT=104, 16kHz) |
| `include/3gpp/rtp/RtcpPacket.hpp` | SR, RR, SDES CNAME, ReceptionReport block, CompoundRtcp builder |
| `include/3gpp/rtp/JitterEstimator.hpp` | RFC 3550 Appendix A.8 interarrival jitter EWMA filter + loss counter |

### Demo Scenario — `demo_05_rtp_stream.cpp`

Simulates a live **VoLTE voice session** over real UDP loopback sockets:

1. **25 RTP packets** sent at 20ms intervals with AMR-WB payload (PT=104, +320 timestamp ticks)
2. **RTCP Sender Report** sent after 13 packets with NTP timestamp, RTP timestamp sync, and cumulative stats
3. **RTCP Receiver Report** sent by receiver with measured interarrival jitter and zero packet loss
4. All 27 packets (25 RTP + 1 RTCP SR + 1 RTCP RR) captured to `output_05_rtp_stream.pcap`

---

## 4. How to Run the Tests & Inspect Output

### Build the Project
```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
```

### Run Unit Tests (Lesson 05 only)
```bash
./build/tests/unit_tests --gtest_filter="*Rtp*:*Rtcp*:*Jitter*"
```

### Run Standalone Demo
```bash
./build/apps/demo_05_rtp_stream
```

### Inspect Output in Wireshark / tcpdump
```bash
tcpdump -r output_05_rtp_stream.pcap -nv
```
In Wireshark: go to **Telephony → RTP → RTP Streams** to see the AMR-WB stream summary. Filter `rtcp` to inspect SR and RR packets with jitter and loss statistics.

---

## 5. Key Engineering Concepts

### Statistical Jitter Estimation (RFC 3550 Appendix A.8)
For two consecutive packets $i-1$ and $i$, let $S_i$ be the RTP send timestamp and $R_i$ be the arrival time in the same clock units:

$$D(i-1, i) = (R_i - R_{i-1}) - (S_i - S_{i-1}) = (R_i - S_i) - (R_{i-1} - S_{i-1})$$

The interarrival jitter $J$ is updated using a first-order low-pass EWMA filter (gain $\alpha = 1/16$):

$$J_i = J_{i-1} + \frac{|D(i-1, i)| - J_{i-1}}{16}$$

### RTCP Port Convention (RFC 3550 §11)
By convention, RTCP always runs on the port immediately above the RTP port: if RTP is on port `N`, then RTCP is on port `N+1`. Both must be even/odd pairs. This convention is negotiated in SDP (the `a=rtcp:` attribute or the implied `m=audio <port>` + 1).

### Marker Bit (Talkspurt Boundary)
The RTP `M` bit is set to `1` on the **first RTP packet following a period of silence** (DTX — Discontinuous Transmission). This allows the receiver's jitter buffer to be reset at talkspurt boundaries, reducing the initial playout delay for new speech bursts.

---

## 6. Wireshark Analysis

Open `output_05_rtp_stream.pcap` and verify:

```
Frames 1-25:  UE1 → UE2   RTP   PT=104 (AMR-WB), Seq=1001..1025, TS=3200..11200
Frame 14:     UE1 → UE2   RTCP  SR (Sender Report), Packets Sent=13
Frame 26:     UE2 → UE1   RTCP  RR (Receiver Report), Jitter≈11ms, Lost=0
```

In Wireshark:
1. Open `output_05_rtp_stream.pcap`
2. Navigate to **Telephony → RTP → RTP Streams** to see the stream summary (SSRC, codec, packet count, loss %)
3. Filter by `rtcp` to inspect SR and RR packet contents
4. Click on any RTP packet to expand the **Real-Time Transport Protocol** subtree and verify sequence/timestamp progression

```bash
tcpdump -r output_05_rtp_stream.pcap -nv
```

---

## 7. Test Cases (`test_05_rtp.cpp`)

| Test | Description |
|------|-------------|
| `RtpTest.HeaderSerializationRoundTrip` | Encode RTP header fields → deserialize → compare all fields |
| `RtpTest.CsrcListHandling` | RTP header with CC=2 CSRC list encode/decode |
| `RtpTest.AmrWbFactoryPacket` | Factory creates PT=104, 16kHz clock AMR-WB packet |
| `RtcpTest.ReceptionReportBlock` | RTCP RR block with fraction lost, jitter, LSR fields |
| `RtcpTest.CompoundSenderReport` | RTCP compound: SR + SDES CNAME + RR block |
| `RtcpTest.CompoundReceiverReport` | RTCP compound: RR-only with multiple report blocks |
| `JitterTest.SmoothJitterCalculation` | RFC 3550 Appendix A.8 EWMA jitter convergence test |

---

## 8. References

| Specification | Title |
|--------------|-------|
| **RFC 3550** | RTP: A Transport Protocol for Real-Time Applications |
| **RFC 3551** | RTP Profile for Audio and Video Conferences with Minimal Control |
| **RFC 4867** | RTP Payload Format for AMR and AMR-WB |
| **RFC 3389** | RTP Payload for Comfort Noise (CN) |
| **3GPP TS 26.114** | Media Handling and Interaction for IMS Multimedia Telephony |
| **3GPP TS 26.201** | Speech Codec Speech Processing Functions — AMR-WB |
| **3GPP TS 26.441** | Codec for Enhanced Voice Services (EVS) |
| **3GPP TS 23.228** | IP Multimedia Subsystem (IMS) — Stage 2 |
