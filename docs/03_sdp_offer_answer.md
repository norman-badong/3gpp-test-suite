# Lesson 03: SDP (Session Description Protocol) & Offer/Answer Model

## Overview

**SDP (Session Description Protocol)** is the negotiation language used by VoLTE and VoNR UEs to agree on the audio codec, RTP port, direction, and media parameters before voice media begins flowing. It is not a standalone protocol — SDP is always **carried as the body inside SIP messages** (INVITE / 200 OK).

This lesson covers:
- **RFC 4566**: SDP syntax — `v=`, `o=`, `s=`, `c=`, `t=`, `m=`, `a=` line types
- **RFC 3264**: Bidirectional Offer/Answer model — codec matching, port rejection, direction negotiation
- **3GPP TS 26.114**: Mandatory codec profiles for IMS Multimedia Telephony (EVS, AMR-WB, AMR)

### 3GPP Context

| Interface | Between | SDP Role |
|-----------|---------|---------|
| **Gm (IMS)** | UE ↔ P-CSCF | SDP carried inside SIP INVITE / 200 OK |
| **VoLTE (4G)** | Caller UE ↔ Callee UE | AMR-WB mandatory codec, PT=104 |
| **VoNR (5G)** | Caller UE ↔ Callee UE | EVS primary codec, AMR-WB fallback |
| **WebRTC / IMS** | Browser / App ↔ IMS | SDP for codec interoperability |

---

## 1. Protocol Structure

### SDP Syntax (RFC 4566)

SDP is a text-based format. Each line is `<type>=<value>\r\n` with fixed ordering:

```
v=0
o=- 1700000000 1 IN IP4 192.168.1.10
s=3GPP VoLTE Call
c=IN IP4 192.168.1.10
t=0 0
m=audio 49170 RTP/AVP 104 101
a=rtpmap:104 AMR-WB/16000
a=fmtp:104 octet-align=1;mode-change-capability=2
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
```

### Key SDP Field Reference

| Line | Name | 3GPP VoLTE/VoNR Significance |
|------|------|------------------------------|
| `v=0` | Protocol Version | Always `0` per RFC 4566 |
| `o=` | Origin | Unique session ID and version for tracking |
| `s=` | Session Name | Human-readable session title |
| `c=` | Connection Data | Media destination endpoint (`IN IP4` or `IN IP6`) |
| `t=` | Timing | `0 0` for non-bounded (indefinite) calls |
| `m=` | Media Description | Type, RTP port, transport, payload type list |
| `a=rtpmap` | RTP Map | Binds payload type number to codec name and clock rate |
| `a=fmtp` | Format Parameters | Codec-specific config (e.g. `octet-align=1`, `br=13.2-24.4`) |
| `a=sendrecv` | Direction | `sendrecv` / `sendonly` / `recvonly` / `inactive` |
| `a=maxptime` | Max Packet Time | Maximum RTP packet duration in ms (typically 40ms) |

---

## 2. 3GPP Protocol Flow

### VoNR → VoLTE Cross-Codec Negotiation

```
       Caller (5G VoNR UE)                     Callee (4G VoLTE UE)
               |                                        |
               | --- SIP INVITE (SDP Offer)          -> |
               |     m=audio 49170 RTP/AVP 108 104 101  |
               |     a=rtpmap:108 EVS/16000              |
               |     a=rtpmap:104 AMR-WB/16000           |
               |     a=rtpmap:101 telephone-event/8000   |
               |                                        |
               | <- SIP 200 OK (SDP Answer)          -- |
               |     m=audio 50004 RTP/AVP 104 101      |
               |     a=rtpmap:104 AMR-WB/16000           |
               |     a=rtpmap:101 telephone-event/8000   |
               |                                        |
               | <====== Bi-directional RTP Audio ====> |
               |     (AMR-WB PT=104, to negotiated ports)|
```

### RFC 3264 Offer/Answer Negotiation Rules

| Rule | Behaviour |
|------|-----------|
| **Codec Matching** | Answerer selects matching codecs using the **same payload type numbers** from the Offer |
| **Port Rejection** | If no common voice codec exists, Answerer sets `port=0` to reject the media line |
| **Direction** | `sendrecv` Offer → Answerer may reply with `sendrecv`, `sendonly`, `recvonly`, or `inactive` |
| **Hold** | `sendonly` Offer (call hold) → Answerer MUST reply with `recvonly` |
| **DTMF** | `telephone-event` (RFC 4733) only included in Answer if at least one voice codec matched |

---

## 3. Project Implementation

### Source Files

| File | Description |
|------|-------------|
| `include/3gpp/sdp/Sdp.hpp` | RFC 4566 parser and generator; VoLTE AMR-WB and VoNR EVS offer factories |
| `include/3gpp/sdp/SdpNegotiator.hpp` | RFC 3264 codec matching, port-zero rejection, direction negotiation |

### Demo Scenario — `demo_03_sdp_negotiate.cpp`

Simulates a full **VoNR (5G EVS) → VoLTE (4G AMR-WB)** SDP offer/answer exchange:

1. **SDP Offer** — 5G caller generates offer: EVS (PT=108) + AMR-WB (PT=104) + telephone-event
2. **SDP Answer** — 4G callee negotiator selects AMR-WB (PT=104) only (no EVS support)
3. **Direction** — Both sides agree on `sendrecv`
4. **DTMF** — `telephone-event` retained since AMR-WB matched
5. Both messages serialized and captured to `output_03_sdp_negotiate.pcap`

---

## 4. How to Run the Tests & Inspect Output

### Build the Project
```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
```

### Run Unit Tests (Lesson 03 only)
```bash
./build/tests/unit_tests --gtest_filter="*Sdp*"
```

### Run Standalone Demo
```bash
./build/apps/demo_03_sdp_negotiate
```

### Inspect Output in Wireshark / tcpdump
```bash
tcpdump -r output_03_sdp_negotiate.pcap -nvX
```
Wireshark dissects the frames into full `SIP INVITE` and `SIP 200 OK` packets with nested RFC 4566 Session Description Protocol structures showing each `m=`, `a=rtpmap`, and `a=fmtp` line decoded.

---

## 5. Key Engineering Concepts

### Dynamic Payload Type Assignment
Codec payload type numbers in the range 96–127 are **dynamic** — negotiated per-session in SDP. The `a=rtpmap` attribute binds the dynamic number (e.g. `104`) to the codec name and clock rate (e.g. `AMR-WB/16000`). The Answerer must preserve the exact PT numbers from the Offer.

### Strict `rtpmap` + `fmtp` Pairing
Per RFC 4566, each `a=fmtp:<pt>` line must immediately follow its corresponding `a=rtpmap:<pt>` to preserve ordered association. A parser that separates them will break parameter lookup for multi-codec sessions.

### EVS Codec (Enhanced Voice Services)
3GPP TS 26.441 defines EVS as the successor to AMR-WB for 5G VoNR, supporting bitrates from 5.9 kbps to 128 kbps and super-wideband (SWB, 14 kHz) / fullband (FB, 20 kHz) audio. The SDP `a=fmtp` for EVS uses `br=` (bitrate range) and `bw=` (bandwidth mode) parameters.

---

## 6. Wireshark Analysis

Open `output_03_sdp_negotiate.pcap` and verify:

```
Frame 1: 192.168.1.10 → 192.168.1.1   SIP INVITE  [SDP Offer: EVS + AMR-WB + telephone-event]
Frame 2: 192.168.1.1  → 192.168.1.10  SIP 200 OK  [SDP Answer: AMR-WB only, sendrecv]
```

In Wireshark: expand the SIP message → `Message body` → `Session Description Protocol`:
- Confirm `m=audio 49170 RTP/AVP 108 104 101` in the Offer
- Confirm `m=audio 50004 RTP/AVP 104 101` in the Answer (EVS PT=108 absent)
- Check `a=fmtp:104 octet-align=1` on the Answer codec parameters

```bash
tcpdump -r output_03_sdp_negotiate.pcap -nvX
```

---

## 7. Test Cases (`test_03_sdp.cpp`)

| Test | Description |
|------|-------------|
| `SdpTest.RtpMapAndFmtpParsing` | Parse `a=rtpmap` and `a=fmtp` lines and verify codec binding |
| `SdpTest.VoLteOfferGeneration` | Factory generates correct VoLTE AMR-WB SDP offer structure |
| `SdpTest.ParseAndSerializeRoundTrip` | Full SDP parse → serialize preserves all fields and ordering |
| `SdpNegotiationTest.MatchedCodecSelection` | Answerer selects AMR-WB from multi-codec EVS+AMR-WB offer |
| `SdpNegotiationTest.IncompatibleCodecRejection` | No common codec → Answer sets `port=0` |
| `SdpNegotiationTest.DirectionNegotiation` | `sendonly` offer → Answerer must reply `recvonly` |

---

## 8. References

| Specification | Title |
|--------------|-------|
| **RFC 4566** | SDP: Session Description Protocol |
| **RFC 3264** | An Offer/Answer Model with SDP |
| **RFC 4867** | RTP Payload Format and File Storage Format for AMR and AMR-WB |
| **RFC 4733** | RTP Payload for DTMF Digits, Telephony Tones and Signals |
| **3GPP TS 26.114** | Media Handling and Interaction for IMS Multimedia Telephony |
| **3GPP TS 26.441** | Codec for Enhanced Voice Services (EVS) |
| **3GPP TS 26.201** | Speech Codec Speech Processing Functions — AMR-WB |
| **3GPP TS 24.229** | IP Multimedia Call Control Protocol Based on SIP and SDP |
