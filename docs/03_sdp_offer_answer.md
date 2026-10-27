# Lesson 03: SDP (Session Description Protocol) & Offer/Answer Model

## 1. 3GPP Relevance & Architecture Context

In **VoLTE (4G Voice over LTE)** and **VoNR (5G Voice over New Radio)**, media sessions are established within the **IP Multimedia Subsystem (IMS)**.

While SIP (Lesson 04) handles the signaling exchange between the User Equipment (UE) and the P-CSCF (Proxy-Call Session Control Function), SIP delegates media capability negotiation to **SDP (Session Description Protocol)** carried inside the SIP body:

- **RFC 4566:** Defines the SDP syntax (`v=`, `o=`, `s=`, `c=`, `t=`, `m=`, `a=`).
- **RFC 3264:** Defines the bidirectional **Offer/Answer Model**:
  - The caller sends an **SDP Offer** specifying supported codecs, dynamic payload types, and receiving RTP ports.
  - The callee responds with an **SDP Answer** selecting matching codecs and binding its own receiving RTP port.
- **3GPP TS 26.114:** Specifies mandatory codecs for IMS Multimedia Telephony:
  - **EVS (Enhanced Voice Services, TS 26.441):** Primary HD/super-wideband codec for 5G VoNR.
  - **AMR-WB (Adaptive Multi-Rate Wideband, G.722.2):** Mandatory HD codec for 4G VoLTE.
  - **AMR (Narrowband):** Standard legacy cellular voice codec.
  - **telephone-event:** RFC 4733 DTMF dual-tone multi-frequency signaling.

```
       Caller (5G VoNR UE)                     Callee (4G VoLTE UE)
               |                                        |
               | --- SIP INVITE (SDP Offer: EVS,AMR) -> |
               |     [m=audio 49170 RTP/AVP 108 104]    |
               |                                        |
               | <-- SIP 200 OK (SDP Answer: AMR-WB) -- |
               |     [m=audio 50004 RTP/AVP 104]        |
               |                                        |
               | <====== Bi-directional RTP Voice =====>|
               |     (Sent to Negotiated Ports)         |
```

---

## 2. Key SDP Fields & Attributes Implemented

| Line | Name | 3GPP VoLTE/VoNR Significance |
| :--- | :--- | :--- |
| `v=0` | Protocol Version | Always 0 per RFC 4566. |
| `o=` | Owner / Creator | Unique session ID and version for session tracking. |
| `s=` | Session Name | Session title (e.g. `3GPP VoLTE Call`). |
| `c=` | Connection Data | Media destination endpoint (`IN IP4 <ip>` or `IN IP6 <ip>`). |
| `t=` | Time Active | Start and stop times (`0 0` for non-bounded calls). |
| `m=` | Media Description | Media type (`audio`), RTP receiving port, transport protocol (`RTP/AVP`), and format list. |
| `a=rtpmap` | Dynamic Payload Type | Binds payload numbers to codec names and clock rates (e.g. `104 AMR-WB/16000`). |
| `a=fmtp` | Format Parameters | Codec-specific properties (e.g. `octet-align=1`, `mode-change-capability=2`, `br=13.2-24.4; bw=wb-swb`). |
| `a=sendrecv` | Direction Attribute | Bidirectional voice (`sendrecv`), Call hold (`sendonly` / `recvonly`), or Mute (`inactive`). |

---

## 3. Offer/Answer Negotiation Rules (RFC 3264)

1. **Codec Matching:**
   - The Answerer must pick matching codecs and keep the same dynamic payload type numbers offered by the Caller.
   - If no common voice codec can be agreed upon, the media stream is rejected by setting the port to `0` (`m=audio 0 RTP/AVP ...`).
2. **Direction Negotiation:**
   - `sendrecv` in Offer $\rightarrow$ Answerer can accept as `sendrecv`, `sendonly`, `recvonly`, or `inactive`.
   - `sendonly` in Offer (e.g. Caller puts call on hold) $\rightarrow$ Answerer MUST reply with `recvonly`.
3. **DTMF Signaling:**
   - `telephone-event` (RFC 4733) is negotiated alongside audio codecs so in-band DTMF keys are transmitted reliably over RTP.

---

## 4. How to Run the Tests & Inspect Output

### Run Unit Tests
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
Wireshark dissects the frames into full `SIP INVITE` and `SIP 200 OK` packets with nested RFC 4566 Session Description Protocol structures.
