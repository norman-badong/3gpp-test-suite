# Lesson 04: SIP (Session Initiation Protocol) & VoLTE / VoNR Call Control

## 1. 3GPP Relevance & Architecture Context

In **4G VoLTE** and **5G VoNR**, all voice call setup, maintenance, tear-down, supplementary services (call forwarding, call hold), and emergency routing are controlled through **SIP (Session Initiation Protocol)** over the **IP Multimedia Subsystem (IMS)**:

- **RFC 3261:** Core SIP specification defining User Agent Client (UAC), User Agent Server (UAS), Proxies, Registrars, and Transactions/Dialogs.
- **3GPP TS 24.229:** 3GPP IMS call control protocol based on SIP and SDP.
- **RFC 3262 (100rel):** Reliability of provisional responses (`183 Session Progress` and `PRACK`) for cellular early media ringback.

```
       UE (Caller)                      P-CSCF / IMS Core                  UE (Callee)
           |                                   |                                |
1. REGISTER| --------------------------------> |                                |
2. 200 OK  | <-------------------------------- |                                |
           |                                   |                                |
3. INVITE  | --------------------------------> | -----------------------------> | (SDP Offer)
4. 180 Ring| <-------------------------------- | <----------------------------- | (Ringing)
5. 200 OK  | <-------------------------------- | <----------------------------- | (SDP Answer)
6. ACK     | --------------------------------> | -----------------------------> |
           |                                   |                                |
           | <=========== RTP Audio Media (Lesson 05) ========================> |
           |                                   |                                |
7. BYE     | --------------------------------> | -----------------------------> |
8. 200 OK  | <-------------------------------- | <----------------------------- |
```

---

## 2. Core Protocol Elements Implemented

### SIP URIs (RFC 3261 Section 19.1)
- Format: `sip:user@domain:port;parameters`
- Supports telephone numbers: `sip:+14155551234@ims.mnc001.mcc001.3gppnetwork.org;user=phone`

### Core Headers
- **`Via`:** Records the network transport path taken by the request and provides the route for responses (`branch=z9hG4bK...`, `rport`).
- **`From`:** Originator URI and unique local `tag`.
- **`To`:** Destination URI and callee `tag` (assigned on response).
- **`Call-ID`:** Globally unique identifier for the call session (`<random>@<host>`).
- **`CSeq`:** Monotonically increasing sequence number + method (`101 INVITE`, `102 BYE`).
- **`Contact`:** Direct IP address and port of the User Agent where subsequent in-dialog requests must be routed.

### Compact Header Normalization
Per RFC 3261 Section 7.3.3, mobile devices on bandwidth-constrained cellular links frequently use single-letter compact headers:
`v` (Via), `f` (From), `t` (To), `i` (Call-ID), `m` (Contact), `c` (Content-Type), `l` (Content-Length), `k` (Supported). The parser transparently handles both long and compact formats interchangeably.

---

## 3. SIP Dialog State Machine

A dialog represents a persistent peer-to-peer relationship between two SIP user agents:

```
+--------+   INVITE Sent    +-------+   180 Ringing (with tag)   +-------+
|  IDLE  | ---------------> | EARLY | ------------------------> | EARLY |
+--------+                  +-------+                           +-------+
                                |                                   |
                                | 200 OK (with tag) + ACK           | 200 OK + ACK
                                v                                   v
                         +-------------+                     +-------------+
                         |  CONFIRMED  | <------------------ |  CONFIRMED  |
                         +-------------+                     +-------------+
                                |
                                | BYE sent / received
                                v
                         +-------------+
                         | TERMINATED  |
                         +-------------+
```

---

## 4. How to Run the Tests & Inspect Output

### Run Unit Tests
```bash
./build/tests/unit_tests --gtest_filter="*Sip*"
```

### Run Standalone Demo
```bash
./build/apps/demo_04_sip_volte_call
```

### Inspect Output in Wireshark / tcpdump
```bash
tcpdump -r output_04_sip_volte_call.pcap -nvX
```
In Wireshark:
- Open `output_04_sip_volte_call.pcap`.
- Navigate to **Telephony $\rightarrow$ VoIP Calls** to view the call flow diagram with registration, ringing, media answer, and call teardown.
