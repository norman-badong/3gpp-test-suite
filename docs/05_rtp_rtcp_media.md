# Lesson 05: RTP & RTCP (Real-time Transport & Control Protocol)

## 1. 3GPP Relevance & Architecture Context

In **4G VoLTE** and **5G VoNR**, while SIP (Lesson 04) negotiates the call parameters using SDP (Lesson 03), the actual voice/audio bitstream is delivered in real-time over **RTP (Real-time Transport Protocol, RFC 3550)**, monitored out-of-band by **RTCP (RTP Control Protocol)**:

- **RFC 3550:** Core RTP and RTCP framing, timing, sequence numbering, and jitter estimation.
- **RFC 3551:** RTP Audio/Video profile for minimal control.
- **3GPP TS 26.114:** Media Handling and Interaction for IMS Multimedia Telephony.
- **3GPP TS 26.201 / RFC 4867:** AMR-WB audio frame payload format (Octet-aligned and Bandwidth-efficient modes).

```
         Caller (UE1)                                   Callee (UE2)
              |                                               |
              | ====== RTP Voice Stream (Port 50004) =======> |
              |      [AMR-WB 16 kHz, 20ms audio frames]       |
              |                                               |
              | ------ RTCP Sender Report (Port 50005) -----> |
              |      [SR: NTP + RTP timestamp, octet count]   |
              |                                               |
              | <----- RTCP Receiver Report (Port 50005) ---- |
              |      [RR: Interarrival jitter, packet loss]   |
```

---

## 2. RTP Voice Packetization Math (3GPP VoLTE / VoNR)

In cellular voice, audio frames are transmitted every **20 milliseconds** to minimize end-to-end voice latency:

$$\text{Clock Rate for AMR-WB} = 16{,}000\text{ Hz}$$
$$\text{Ticks per Frame} = 16{,}000\text{ Hz} \times 0.020\text{ s} = 320\text{ timestamp ticks per packet}$$

| Field | Length | Description in 3GPP VoLTE |
| :--- | :---: | :--- |
| **V (Version)** | 2 bits | Always `2` per RFC 3550. |
| **P (Padding)** | 1 bit | `0` (or `1` if padding octets exist). |
| **X (Extension)** | 1 bit | `0` (or `1` for header extensions). |
| **CC (CSRC Count)** | 4 bits | Number of contributing sources (usually 0). |
| **M (Marker)** | 1 bit | Set to `1` on the first packet of a speech burst (talkspurt) following silence suppression (DTX). |
| **PT (Payload Type)** | 7 bits | Dynamic payload type negotiated in SDP (e.g. `104` for AMR-WB, `108` for EVS). |
| **Sequence Number** | 16 bits | Increments by 1 for each RTP data packet; enables packet reordering and loss detection. |
| **Timestamp** | 32 bits | Increments by 320 for each 20ms speech frame. |
| **SSRC** | 32 bits | Unique 32-bit synchronization source randomly chosen by the UE. |

---

## 3. Statistical Jitter Estimation (RFC 3550 Appendix A.8)

Network packet delay variation (jitter) causes audio distortion and choppy calls if not compensated by a jitter buffer. 

For two consecutive packets $i-1$ and $i$, let $S_i$ be the RTP transmission timestamp and $R_i$ be the arrival time measured in the same clock units (16 kHz).

The transit time difference $D(i-1, i)$ is:
$$D(i-1, i) = (R_i - R_{i-1}) - (S_i - S_{i-1}) = (R_i - S_i) - (R_{i-1} - S_{i-1})$$

The interarrival jitter $J$ is updated using a 1st-order low-pass filter (gain $\alpha = 1/16$):
$$J_i = J_{i-1} + \frac{|D(i-1, i)| - J_{i-1}}{16}$$

---

## 4. How to Run the Tests & Inspect Output

### Run Unit Tests
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
In Wireshark:
1. Open `output_05_rtp_stream.pcap`.
2. Go to **Telephony $\rightarrow$ RTP $\rightarrow$ RTP Streams**.
3. Wireshark detects the active AMR-WB audio stream, 0% packet loss, sequence regularity, and jitter analysis.
4. Filter by `rtcp` to inspect Sender Reports (SR), Receiver Reports (RR), and SDES CNAME records.
