  # Lesson 10: STUN/TURN/ICE + SOS Emergency Services

  Overview

  STUN (Session Traversal Utilities for NAT), TURN (Traversal Using Relays around NAT), and ICE (Interactive Connectivity
  Establishment) form the NAT traversal foundation for real-time communications in 3GPP networks. Combined with 3GPP Emergency
  Services (TS 23.167, TS 24.229, RFC 6442), this lesson implements the complete signaling path for VoWiFi/VoLTE emergency calls
  with location conveyance.

  This lesson covers:
  - STUN (RFC 5389): Binding Request/Response for reflexive address discovery
  - TURN (RFC 8656): Relay allocation, permissions, and channel binding for media relay
  - ICE (RFC 8445): Candidate gathering, connectivity checks, and nominated pair selection
  - Emergency Services (TS 23.167, TS 24.229): Emergency registration, SIP emergency calls, PIDF-LO location conveyance

  3GPP Context

  ┌───────────────────────────┬─────────────────────────┬─────────────┬──────────────────────────────────────────┐
  │         Interface         │         Between         │  Transport  │                 Purpose                  │
  ├───────────────────────────┼─────────────────────────┼─────────────┼──────────────────────────────────────────┤
  │ STUN/TURN (UDP 3478/5349) │ UE ↔ TURN Server        │ UDP/TCP     │ NAT traversal for media (VoWiFi, VoLTE)  │
  ├───────────────────────────┼─────────────────────────┼─────────────┼──────────────────────────────────────────┤
  │ ICE                       │ UE ↔ UE (via signaling) │ UDP         │ Connectivity checks, candidate exchange  │
  ├───────────────────────────┼─────────────────────────┼─────────────┼──────────────────────────────────────────┤
  │ SIP Emergency (IMS)       │ UE ↔ P-CSCF ↔ E-CSCF    │ UDP/TCP/TLS │ Emergency call setup (TS 24.229)         │
  ├───────────────────────────┼─────────────────────────┼─────────────┼──────────────────────────────────────────┤
  │ Location (PIDF-LO)        │ UE → E-CSCF/PSAP        │ SIP body    │ Emergency location conveyance (RFC 6442) │
  ├───────────────────────────┼─────────────────────────┼─────────────┼──────────────────────────────────────────┤
  │ Rx/Gx (Diameter)          │ E-CSCF ↔ PCRF/SPR       │ Diameter    │ Emergency QoS, service urn routing       │
  └───────────────────────────┴─────────────────────────┴─────────────┴──────────────────────────────────────────┘

  ---

  1. Protocol Structure

  STUN Message Format (RFC 5389 §6)

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |0 0|     STUN Message Type     |         Message Length        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Magic Cookie                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  |                     Transaction ID (96 bits)                  |
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  ┌────────────────┬─────────┬────────────────────────────────────────────────────────────────────────────────────────────────┐
  │     Field      │  Size   │                                       Value/Description                                        │
  ├────────────────┼─────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Message Type   │ 16 bits │ Method (bits 0-11) + Class (bits 12-15): Request=0x0, Success=0x1, Error=0x11, Indication=0x10 │
  ├────────────────┼─────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Message Length │ 16 bits │ Length of attributes in bytes (excluding 20-byte header)                                       │
  ├────────────────┼─────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Magic Cookie   │ 32 bits │ Fixed 0x2112A442 (RFC 5389)                                                                    │
  ├────────────────┼─────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Transaction ID │ 96 bits │ Random, matches request/response                                                               │
  └────────────────┴─────────┴────────────────────────────────────────────────────────────────────────────────────────────────┘

  Message Types (Method + Class):

  ┌─────────────────────────┬─────────┬──────────────────┬────────────────┬────────────┐
  │         Method          │ Request │ Success Response │ Error Response │ Indication │
  ├─────────────────────────┼─────────┼──────────────────┼────────────────┼────────────┤
  │ Binding                 │ 0x0001  │ 0x0101           │ 0x0111         │ 0x0011     │
  ├─────────────────────────┼─────────┼──────────────────┼────────────────┼────────────┤
  │ Allocate (TURN)         │ 0x0003  │ 0x0103           │ 0x0113         │ —          │
  ├─────────────────────────┼─────────┼──────────────────┼────────────────┼────────────┤
  │ Refresh (TURN)          │ 0x0004  │ 0x0104           │ 0x0114         │ —          │
  ├─────────────────────────┼─────────┼──────────────────┼────────────────┼────────────┤
  │ CreatePermission (TURN) │ 0x0005  │ 0x0105           │ 0x0115         │ —          │
  ├─────────────────────────┼─────────┼──────────────────┼────────────────┼────────────┤
  │ ChannelBind (TURN)      │ 0x0006  │ 0x0106           │ 0x0116         │ —          │
  └─────────────────────────┴─────────┴──────────────────┴────────────────┴────────────┘

  STUN Attributes (TLV Format)

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Attribute Type        |         Attribute Length      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Attribute Value                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Key Attributes:

  ┌────────────────────┬────────┬────────────────────────────────────────────────┐
  │     Attribute      │  Type  │                  Description                   │
  ├────────────────────┼────────┼────────────────────────────────────────────────┤
  │ XOR-MAPPED-ADDRESS │ 0x0020 │ Reflexive address (XOR'd with magic cookie)    │
  ├────────────────────┼────────┼────────────────────────────────────────────────┤
  │ MAPPED-ADDRESS     │ 0x0001 │ Reflexive address (legacy)                     │
  ├────────────────────┼────────┼────────────────────────────────────────────────┤
  │ USERNAME           │ 0x0006 │ Username for authentication                    │
  ├────────────────────┼────────┼────────────────────────────────────────────────┤
  │ MESSAGE-INTEGRITY  │ 0x0008 │ HMAC-SHA1 over message                         │
  ├────────────────────┼────────┼────────────────────────────────────────────────┤
  │ FINGERPRINT        │ 0x8028 │ CRC-32 XOR'd with magic cookie                 │
  ├────────────────────┼────────┼────────────────────────────────────────────────┤
  │ ERROR-CODE         │ 0x0009 │ Error class (100-600) + number (0-99) + reason │
  ├────────────────────┼────────┼────────────────────────────────────────────────┤
  │ REALM              │ 0x0014 │ Authentication realm                           │
  ├────────────────────┼────────┼────────────────────────────────────────────────┤
  │ NONCE              │ 0x0015 │ Server nonce for digest auth                   │
  ├────────────────────┼────────┼────────────────────────────────────────────────┤
  │ SOFTWARE           │ 0x8022 │ Server/client software identifier              │
  └────────────────────┴────────┴────────────────────────────────────────────────┘

  TURN Attributes (RFC 8656):

  ┌─────────────────────┬────────┬──────────────────────────────────────────┐
  │      Attribute      │  Type  │               Description                │
  ├─────────────────────┼────────┼──────────────────────────────────────────┤
  │ CHANNEL-NUMBER      │ 0x000C │ Channel binding (0x4000-0x7FFE)          │
  ├─────────────────────┼────────┼──────────────────────────────────────────┤
  │ LIFETIME            │ 0x000D │ Allocation/permission lifetime (seconds) │
  ├─────────────────────┼────────┼──────────────────────────────────────────┤
  │ XOR-PEER-ADDRESS    │ 0x0012 │ Peer address for permission/channel      │
  ├─────────────────────┼────────┼──────────────────────────────────────────┤
  │ DATA                │ 0x0013 │ Application data (Send/Data indication)  │
  ├─────────────────────┼────────┼──────────────────────────────────────────┤
  │ XOR-RELAYED-ADDRESS │ 0x0016 │ Allocated relay address                  │
  ├─────────────────────┼────────┼──────────────────────────────────────────┤
  │ EVEN-PORT           │ 0x0017 │ Request even port number                 │
  ├─────────────────────┼────────┼──────────────────────────────────────────┤
  │ REQUESTED-TRANSPORT │ 0x0019 │ Transport protocol (UDP=17)              │
  ├─────────────────────┼────────┼──────────────────────────────────────────┤
  │ DONT-FRAGMENT       │ 0x001A │ Set DF bit on relayed packets            │
  ├─────────────────────┼────────┼──────────────────────────────────────────┤
  │ PRIORITY            │ 0x0024 │ ICE candidate priority                   │
  ├─────────────────────┼────────┼──────────────────────────────────────────┤
  │ USE-CANDIDATE       │ 0x0025 │ Nominate this candidate pair             │
  ├─────────────────────┼────────┼──────────────────────────────────────────┤
  │ ICE-CONTROLLING     │ 0x8029 │ Controlling role tie-breaker             │
  ├─────────────────────┼────────┼──────────────────────────────────────────┤
  │ ICE-CONTROLLED      │ 0x802A │ Controlled role tie-breaker              │
  └─────────────────────┴────────┴──────────────────────────────────────────┘

  TURN Channel Data (RFC 8656 §11)

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Channel Number        |           Length              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  |                    Application Data                           |
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  - Channel Number: 0x4000 to 0x7FFE (distinguished from STUN by MSB=01)
  - Length: Application data length in bytes
  - No STUN header — lightweight data path

  ICE Candidate (RFC 8445 §5.1)

  SDP a=candidate: Line Format:
  a=candidate:<foundation> <component> <transport> <priority> <ip> <port> typ <type>
               [raddr <rel-addr> rport <rel-port>] [tcptype <tcptype>]

  ┌──────────────┬──────────────────────────────────────────────────────────────────────┐
  │    Field     │                             Description                              │
  ├──────────────┼──────────────────────────────────────────────────────────────────────┤
  │ Foundation   │ Arbitrary string, same for candidates from same base                 │
  ├──────────────┼──────────────────────────────────────────────────────────────────────┤
  │ Component ID │ 1=RTP, 2=RTCP (RTCP mux uses only 1)                                 │
  ├──────────────┼──────────────────────────────────────────────────────────────────────┤
  │ Transport    │ UDP or TCP                                                           │
  ├──────────────┼──────────────────────────────────────────────────────────────────────┤
  │ Priority     │ 32-bit: (type_pref << 24) | (local_pref << 8) | (256 - component_id) │
  ├──────────────┼──────────────────────────────────────────────────────────────────────┤
  │ IP/Port      │ Candidate transport address                                          │
  ├──────────────┼──────────────────────────────────────────────────────────────────────┤
  │ Type         │ host, srflx, prflx, relay                                            │
  ├──────────────┼──────────────────────────────────────────────────────────────────────┤
  │ raddr/rport  │ Related address (base for srflx/relay)                               │
  ├──────────────┼──────────────────────────────────────────────────────────────────────┤
  │ tcptype      │ active, passive, so (TCP only)                                       │
  └──────────────┴──────────────────────────────────────────────────────────────────────┘

  Type Preferences (RFC 8445 §5.1.2):

  ┌───────┬────────────┬──────────────────────────┐
  │ Type  │ Preference │       Typical Use        │
  ├───────┼────────────┼──────────────────────────┤
  │ host  │ 126        │ Direct local interface   │
  ├───────┼────────────┼──────────────────────────┤
  │ srflx │ 110        │ STUN-derived reflexive   │
  ├───────┼────────────┼──────────────────────────┤
  │ prflx │ 110        │ Peer-reflexive (learned) │
  ├───────┼────────────┼──────────────────────────┤
  │ relay │ 0          │ TURN relayed             │
  └───────┴────────────┴──────────────────────────┘

  ICE Connectivity Checks (RFC 8445 §7)

  Check List Formation:
  1. Form all local × remote candidate pairs (same component, same transport)
  2. Compute pair priority: 2^32 × min(G,D) + 2 × max(G,D) + (G>D ? 1 : 0)
  3. Sort by priority descending
  4. Unfreeze first pair per foundation

  Check States: Frozen → Waiting → InProgress → Succeeded/Failed

  Nomination:
  - Controlling agent includes USE-CANDIDATE to nominate
  - Controlled agent accepts nomination
  - First nominated pair becomes the selected pair for media

  3GPP Emergency Call Flow (TS 24.229 §5.1.2)

  UE                                                    P-CSCF                    E-CSCF                  PSAP
   |                                                      |                         |                       |
   |==== REGISTER (emergency) ============================>|                         |                       |
   |   Emergency registration (no SIM / limited service)   |                         |                       |
   |<=== 200 OK (with GRUU, route set) ===================|                         |                       |
   |                                                      |                         |                       |
   |==== INVITE (urn:service:sos) =======================>|=========================>|                       |
   |   Priority: emergency                                |   Route: E-CSCF        |                       |
   |   Geolocation: <cid:location@call-id>                |   Location: PIDF-LO    |                       |
   |   SDP offer (ICE candidates)                         |   SDP offer            |                       |
   |                                                      |                         |                       |
   |<=== 183 Session Progress ============================|<========================|                       |
   |   SDP answer (ICE candidates)                        |                         |                       |
   |                                                      |                         |                       |
   |<=== 200 OK ==========================================|<========================|                       |
   |   Session-Expires                                    |                         |                       |
   |==== ACK ============================================>|=========================>|                       |
   |                                                      |                         |                       |
   |==== UPDATE (location update) =======================>|=========================>|                       |
   |   PIDF-LO with updated location                      |   PIDF-LO              |                       |
   |                                                      |                         |                       |
   |==== BYE ============================================>|=========================>|                       |
   |                                                      |                         |                       |

  PIDF-LO Location Format (RFC 6442, RFC 4119)

  <?xml version="1.0" encoding="UTF-8"?>
  <presence xmlns="urn:ietf:params:xml:ns:pidf"
            xmlns:gp="urn:ietf:params:xml:ns:pidf:geopriv10"
            xmlns:gs="http://www.opengis.net/pidflo/1.0"
            xmlns:gml="http://www.opengis.net/gml"
            entity="sip:user@example.com">
    <tuple id="tuple1">
      <gp:geopriv>
        <gp:location-info>
          <gs:Circle srsName="urn:ogc:def:crs:EPSG::4326">
            <gml:pos>37.7749 -122.4194</gml:pos>
            <gs:radius>15.0</gs:radius>
          </gs:Circle>
          <gs:civicAddress>
            <gp:country>US</gp:country>
            <gp:A1>CA</gp:A1>
            <gp:A3>San Francisco</gp:A3>
            <gp:A4>Market St</gp:A4>
            <gp:A5>100</gp:A5>
          </gs:civicAddress>
        </gp:location-info>
        <gp:method>GPS</gp:method>
        <gp:confidence>0.95</gp:confidence>
      </gp:geopriv>
      <timestamp>1234567890</timestamp>
    </tuple>
  </presence>

  Geolocation Header (RFC 6442)

  Geolocation: <cid:location@call-id>;routing=yes;purpose=emergency
  Content-ID: <location@call-id>
  Content-Type: application/pidf+xml
  Content-Disposition: render

  ---

  2. 3GPP Protocol Flow

  Emergency Registration (TS 24.229 §5.1.2.2)

  1. UE → P-CSCF: REGISTER with Contact containing +sip.instance and reg-id=1
  2. P-CSCF → UE: 401 Unauthorized with WWW-Authenticate (if credentials needed)
  3. UE → P-CSCF: REGISTER with Authorization header (AKA/HTTP Digest)
  4. P-CSCF → UE: 200 OK with Service-Route, Path, Contact (GRUU), Expires
  5. UE stores route set for subsequent emergency requests

  Emergency Registration Differences:
  - No IMS services (only emergency)
  - Can register without SIM (limited service state)
  - P-Emergency-Info header may indicate emergency registration

  Emergency Call Setup (TS 24.229 §5.1.3)

  1. UE → P-CSCF: INVITE to urn:service:sos[.category]
     - Priority: emergency
     - Geolocation header with CID reference
     - Accept: application/pidf+xml
     - SDP with ICE candidates (a=candidate:, a=ice-ufrag, a=ice-pwd)
     - Multipart body: SDP + PIDF-LO (if location available)
  2. P-CSCF → E-CSCF: INVITE with route set
  3. E-CSCF → PSAP: INVITE routed to appropriate PSAP based on location/service URN
  4. PSAP → E-CSCF: 183 Session Progress / 200 OK with SDP answer
  5. E-CSCF → UE: Response forwarded back
  6. UE → PSAP: ACK
  7. Media: ICE connectivity checks establish media path (RTP/RTCP)

  Location Updates During Call (TS 23.167 §7.4)

  - UE sends UPDATE with new Geolocation + PIDF-LO body
  - Periodic updates (e.g., every 30s) or on significant location change
  - PSAP/E-CSCF updates location display for dispatchers

  ---

  3. Project Implementation

  Header & Source Files

  ┌─────────────────────────────────────────────┬───────────────────────────────────────────────────────────────────────────┐
  │                    File                     │                                Description                                │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────┤
  │ include/3gpp/emergency/EmergencyTypes.hpp   │ Enums, structs for emergency categories, location, QoS, service URNs      │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────┤
  │ include/3gpp/emergency/StunMessage.hpp      │ STUN header, attributes, message encode/decode (RFC 5389)                 │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────┤
  │ include/3gpp/emergency/TurnMessage.hpp      │ TURN client/server, allocation, permissions, channel data (RFC 8656)      │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────┤
  │ include/3gpp/emergency/IceAgent.hpp         │ ICE agent, candidate gathering, checklist, connectivity checks (RFC 8445) │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────┤
  │ include/3gpp/emergency/EmergencySession.hpp │ SIP emergency session, registration, PIDF-LO, location updates            │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────┤
  │ src/emergency/StunMessage.cpp               │ STUN encoding/decoding, HMAC-SHA1, CRC-32 fingerprint                     │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────┤
  │ src/emergency/TurnMessage.cpp               │ TURN client allocate/refresh/bind, server allocation management           │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────┤
  │ src/emergency/IceAgent.cpp                  │ ICE candidate gathering, checklist, checks, nomination                    │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────┤
  │ src/emergency/EmergencySession.cpp          │ Emergency SIP flow, registration, PIDF-LO XML, multipart body             │
  └─────────────────────────────────────────────┴───────────────────────────────────────────────────────────────────────────┘

  Demo Application — apps/demo_10_stun_ice.cpp

  Simulates four integrated scenarios:

  1. STUN Binding Request/Response — Client discovers reflexive address via STUN server
  2. TURN Allocate & Channel Bind — Client allocates relay, creates permission, binds channel, sends data
  3. ICE Connectivity Checks — Two agents gather candidates, exchange, run checks, nominate pair
  4. Emergency Session — Emergency registration → INVITE (Police) → 183/200 → ACK → UPDATE (location) → BYE

  All packets captured to output_10_stun_ice.pcap with synthetic Ethernet/IPv4/UDP headers.

  ---

  4. How to Run the Tests & Inspect Output

  Build the Project

  cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
  cmake --build build -j$(nproc)

  Run Unit Tests (Lesson 10 only)

  ./build/tests/unit_tests --gtest_filter="*Emergency*:*Stun*:*Turn*:*Ice*"

  Run Standalone Demo

  ./build/apps/demo_10_stun_ice

  Inspect Output in tcpdump / Wireshark

  tcpdump -r output_10_stun_ice.pcap -nv

  Or view with detailed hex output:

  tshark -r output_10_stun_ice.pcap -x

  Expected PCAP Frames:

  ┌───────┬────────────────────────────────────────────────────────────────────────┐
  │ Frame │                              Description                               │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ 1     │ STUN Binding Request (Client → Server)                                 │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ 2     │ STUN Binding Response (Server → Client, XOR-MAPPED-ADDRESS)            │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ 3     │ TURN Allocate Request                                                  │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ 4     │ TURN Allocate Response (XOR-RELAYED-ADDRESS)                           │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ 5     │ TURN CreatePermission Request                                          │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ 6     │ TURN CreatePermission Response                                         │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ 7     │ TURN ChannelBind Request (channel 0x4000)                              │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ 8     │ TURN ChannelBind Response                                              │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ 9     │ TURN ChannelData (channel 0x4000, "Hello")                             │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ 10+   │ ICE connectivity checks (Binding Request/Response with ICE attributes) │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ N     │ SIP REGISTER (emergency)                                               │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ N+1   │ SIP 200 OK (registration)                                              │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ N+2   │ SIP INVITE (urn:service:sos.police, multipart SDP+PIDF-LO)             │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ N+3   │ SIP 183 Session Progress (SDP answer)                                  │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ N+4   │ SIP 200 OK (Session-Expires)                                           │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ N+5   │ SIP ACK                                                                │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ N+6   │ SIP UPDATE (PIDF-LO location update)                                   │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ N+7   │ SIP 200 OK                                                             │
  ├───────┼────────────────────────────────────────────────────────────────────────┤
  │ N+8   │ SIP BYE                                                                │
  └───────┴────────────────────────────────────────────────────────────────────────┘

  ---

  5. Key Engineering Concepts

  1. STUN XOR Address Obfuscation (RFC 5389 §15.2)

  To prevent ALGs from modifying addresses, STUN XORs the mapped address with the magic cookie:

  XOR-Port = Port ⊕ (MagicCookie >> 16)        // 0x2112
  XOR-IPv4 = IPv4 ⊕ MagicCookie                // 0x2112A442
  XOR-IPv6 = Each 32-bit word ⊕ MagicCookie

  This allows the client to learn its public reflexive address even if a NAT/ALG rewrites the packet.

  2. TURN Relay Allocation (RFC 8656 §6)

  The client sends Allocate request with REQUESTED-TRANSPORT=UDP and LIFETIME. The server responds with:
  - XOR-RELAYED-ADDRESS: The relayed transport address (where peers send media)
  - XOR-MAPPED-ADDRESS: Client's server-reflexive address
  - LIFETIME: Actual allocated lifetime (≤ requested)

  Permissions (RFC 8656 §9): Before relaying data to/from a peer, the client must install a permission via CreatePermission with
  XOR-PEER-ADDRESS. Permissions expire after 300s default.

  Channels (RFC 8656 §11): For lower overhead, ChannelBind binds a CHANNEL-NUMBER (0x4000-0x7FFE) to a peer. Data then flows as
  ChannelData (4-byte header) instead of STUN Send/Data indications.

  3. ICE Candidate Priority Formula (RFC 8445 §5.1.2)

  candidate_priority = (2^24 × type_preference) + (2^8 × local_preference) + (256 - component_id)
  pair_priority      = 2^32 × min(G,D) + 2 × max(G,D) + (G > D ? 1 : 0)

  Where G = controlling agent's candidate priority, D = controlled agent's candidate priority.

  This ensures:
  - Host candidates preferred over srflx over relay
  - Controlling agent's preferences weigh more heavily
  - Deterministic tie-breaking

  4. Emergency Location Conveyance (RFC 6442)

  Location is conveyed in SIP via:
  1. Geolocation header with cid: reference
  2. Content-ID header matching the CID
  3. Multipart MIME body containing:
     - application/sdp (session description)
     - application/pidf+xml (location in PIDF-LO format)

  The routing=yes parameter indicates the location should be routed to the PSAP. The purpose=emergency parameter identifies it as
  emergency location.

  5. PIDF-LO Geodetic vs Civic (RFC 4119, RFC 5139)

  ┌──────────┬──────────────────────────┬──────────────────────────────────────────────────────────────────────────────────────┐
  │   Type   │         Use Case         │                                       Elements                                       │
  ├──────────┼──────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────┤
  │ Geodetic │ GPS, A-GPS, Wi-Fi        │ Latitude, Longitude, Altitude, Accuracy, Confidence                                  │
  │          │ positioning              │                                                                                      │
  ├──────────┼──────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────┤
  │ Civic    │ Address databases, e911  │ Country, State (A1), County (A2), City (A3), Street (A4), House (A5), Building (A6), │
  │          │                          │  Floor (A7), Room (A8)                                                               │
  └──────────┴──────────────────────────┴──────────────────────────────────────────────────────────────────────────────────────┘

  Both can be included simultaneously (LocationType::Both).

  ---

  6. Wireshark Analysis

  Opening output_10_stun_ice.pcap displays the integrated flow:

  Frame 1:   127.0.0.1:5xxxx → 127.0.0.1:3478  STUN  Binding Request
  Frame 2:   127.0.0.1:3478  → 127.0.0.1:5xxxx  STUN  Binding Response (XOR-MAPPED-ADDRESS=127.0.0.1:5xxxx)
  Frame 3:   127.0.0.1:5xxxx → 127.0.0.1:3478  STUN  Allocate Request (REQUESTED-TRANSPORT=UDP, LIFETIME=600)
  Frame 4:   127.0.0.1:3478  → 127.0.0.1:5xxxx  STUN  Allocate Response (XOR-RELAYED-ADDRESS=192.168.0.100:50000)
  Frame 5:   127.0.0.1:5xxxx → 127.0.0.1:3478  STUN  CreatePermission Request (XOR-PEER-ADDRESS=10.0.0.2:6000)
  Frame 6:   127.0.0.1:3478  → 127.0.0.1:5xxxx  STUN  CreatePermission Response
  Frame 7:   127.0.0.1:5xxxx → 127.0.0.1:3478  STUN  ChannelBind Request (CHANNEL=0x4000, XOR-PEER-ADDRESS)
  Frame 8:   127.0.0.1:3478  → 127.0.0.1:5xxxx  STUN  ChannelBind Response
  Frame 9:   127.0.0.1:5xxxx → 127.0.0.1:3478  TURN  ChannelData (CHANNEL=0x4000, DATA="Hello")
  Frames 10-N: ICE Connectivity Checks (STUN Binding with PRIORITY, USE-CANDIDATE, ICE-CONTROLLING)
  Frames N+:   SIP Emergency Registration + Call Flow

  Inspecting STUN Binding Response (Frame 2):
  - Message Type: 0x0101 (Binding Success Response)
  - Magic Cookie: 0x2112A442
  - Transaction ID: matches request
  - Attribute 0x0020 (XOR-MAPPED-ADDRESS): Family=IPv4, XOR-Port=0x7D12 ⊕ 0x2112 = 5C00 (23552), XOR-IP=0x5EFD0443 ⊕ 0x2112A442 =
    7F000001 (127.0.0.1)
  - Attribute 0x8028 (FINGERPRINT): CRC-32 ⊕ 0x2112A442

  Inspecting TURN ChannelData (Frame 9):
  - Channel Number: 0x4000 (MSB 01 distinguishes from STUN)
  - Length: 5
  - Data: 48 65 6C 6C 6F ("Hello")

  Inspecting ICE Connectivity Check:
  - STUN Binding Request with:
    - USERNAME: remote_ufrag:local_ufrag
    - PRIORITY: 2130706431 (host candidate)
    - ICE-CONTROLLING: 0x123456789ABCDEF0 (tie-breaker)
    - USE-CANDIDATE: present (nomination)
  - Response contains XOR-MAPPED-ADDRESS of peer

  Inspecting SIP INVITE (Emergency Call):
  INVITE urn:service:sos.police SIP/2.0
  Via: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK...
  Max-Forwards: 70
  To: <urn:service:sos.police>
  From: <sip:+15551234567@emergency.test>;tag=abc123
  Call-ID: xyz789@127.0.0.1
  CSeq: 1 INVITE
  Contact: <sip:+15551234567@127.0.0.1;transport=UDP>;+sip.instance="<urn:gsma:imei:...>"
  Route: <sip:pcscf.emergency.test;lr>
  Priority: emergency
  Geolocation: <cid:location@xyz789@127.0.0.1>;routing=yes;purpose=emergency
  Content-Type: multipart/mixed;boundary=boundary_abc123
  Content-Length: ...

  --boundary_abc123
  Content-Type: application/sdp
  Content-Disposition: session

  v=0
  o=- 1234567890 1234567890 IN IP4 127.0.0.1
  s=Emergency Call
  c=IN IP4 127.0.0.1
  t=0 0
  m=audio 40000 RTP/AVP 97 98 99
  a=rtpmap:97 AMR-WB/16000
  a=rtpmap:98 AMR/8000
  a=rtpmap:99 EVS/16000
  a=ice-ufrag:AbCd
  a=ice-pwd:EfGhIjKlMnOpQrStUvWxYz
  a=candidate:1 1 UDP 2130706431 127.0.0.1 5000 typ host
  a=candidate:1 1 UDP 1853070335 192.168.0.1 6000 typ srflx raddr 127.0.0.1 rport 5000
  a=candidate:1 1 UDP 110 172.16.0.100 50000 typ relay raddr 192.168.0.1 rport 6000
  --boundary_abc123
  Content-Type: application/pidf+xml
  Content-ID: <location@xyz789@127.0.0.1>
  Content-Disposition: render

  <?xml version="1.0"?>
  <presence entity="sip:+15551234567@emergency.test" ...>
    <tuple id="abc123">
      <gp:geopriv>
        <gp:location-info>
          <gs:Circle srsName="urn:ogc:def:crs:EPSG::4326">
            <gml:pos>37.7749 -122.4194</gml:pos>
            <gs:radius>15.0</gs:radius>
          </gs:Circle>
        </gp:location-info>
        <gp:method>GPS</gp:method>
        <gp:confidence>0.95</gp:confidence>
      </gp:geopriv>
      <timestamp>1234567890</timestamp>
    </tuple>
  </presence>
  --boundary_abc123--

  ---

  7. Test Cases (test_10_emergency.cpp)

  ┌────────────────────────────────────────────────────┬────────────────────────────────────────────────────────────────────────┐
  │                        Test                        │                              Description                               │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ EmergencyTypesTest.EmergencyServiceUrnFromCategory │ Validates service URN mapping for all emergency categories             │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ EmergencyTypesTest.LocationInfo                    │ Tests location presence detection                                      │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ EmergencyTypesTest.EmergencyCallContext            │ Validates call context structure                                       │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ StunMessageTest.BindingRequestEncodeDecode         │ Round-trip STUN Binding Request with fingerprint                       │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ StunMessageTest.BindingResponseEncodeDecode        │ Round-trip STUN Binding Response with XOR-MAPPED-ADDRESS               │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ StunMessageTest.XorAddressIpv6                     │ Validates IPv6 XOR address encoding                                    │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ StunMessageTest.ErrorResponse                      │ STUN error response with error code and reason                         │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ StunMessageTest.MessageIntegrity                   │ HMAC-SHA1 message integrity verification                               │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ StunMessageTest.SoftwareAttribute                  │ SOFTWARE attribute encode/decode                                       │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ TurnMessageTest.ChannelDataEncodeDecode            │ TURN ChannelData 4-byte header + payload                               │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ TurnMessageTest.TurnClientAllocate                 │ Client Allocate request creation                                       │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ TurnMessageTest.TurnClientRefresh                  │ Client Refresh request with credentials                                │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ TurnMessageTest.TurnClientPermission               │ Client CreatePermission request                                        │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ TurnMessageTest.TurnServerAllocate                 │ Server Allocate request handling                                       │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ IceAgentTest.CandidatePriority                     │ Validates type preference ordering (host > srflx > relay)              │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ IceAgentTest.CandidateSdpRoundTrip                 │ ICE candidate SDP a=candidate: encode/decode                           │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ IceAgentTest.CandidateSdpSrflx                     │ Server-reflexive candidate with raddr/rport                            │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ IceAgentTest.IceCredentialsGeneration              │ ufrag/pwd generation (min 4/22 chars)                                  │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ IceAgentTest.AgentCreation                         │ ICE agent initialization with roles                                    │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ IceAgentTest.AgentStartGathering                   │ Host candidate gathering                                               │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ IceAgentTest.PairPriorityComputation               │ Pair priority formula verification                                     │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ EmergencySessionTest.PidfLoXmlGeneration           │ PIDF-LO XML with geodetic location                                     │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ EmergencySessionTest.PidfLoXmlWithCivic            │ PIDF-LO XML with civic address                                         │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ EmergencySessionTest.GeolocationHeader             │ Geolocation header format per RFC 6442                                 │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ EmergencySessionTest.SipMessageEncode              │ SIP message encoding with headers/body                                 │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ EmergencySessionTest.EmergencySessionCreation      │ Emergency session state machine init                                   │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ EmergencySessionTest.EmergencyRegistrationManager  │ Emergency registration flow                                            │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ EmergencyIntegrationTest.StunTurnIceFlow           │ Combined STUN → TURN → ICE component flow                              │
  ├────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ EmergencyIntegrationTest.FullEmergencyCallFlow     │ End-to-end emergency call: REGISTER → INVITE → 183 → 200 → ACK →       │
  │                                                    │ UPDATE → BYE                                                           │
  └────────────────────────────────────────────────────┴────────────────────────────────────────────────────────────────────────┘

  ---

  8. References

  ┌────────────────┬────────────────────────────────────────────────────────────┐
  │ Specification  │                           Title                            │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ RFC 5389       │ Session Traversal Utilities for NAT (STUN)                 │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ RFC 8445       │ Interactive Connectivity Establishment (ICE)               │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ RFC 8656       │ Traversal Using Relays around NAT (TURN)                   │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ RFC 8489       │ STUN/TURN Shared Extensions (obsoletes 5766/5769)          │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ RFC 6442       │ Location Conveyance for SIP (Geolocation header, PIDF-LO)  │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ RFC 4119       │ Presence Information Data Format Location Object (PIDF-LO) │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ RFC 5139       │ Civic Addresses in PIDF-LO                                 │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ RFC 5031       │ Uniform Resource Name (URN) for Emergency Services         │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ RFC 3261       │ SIP: Session Initiation Protocol                           │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ RFC 4412       │ Communications Resource Priority for SIP (Priority header) │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ 3GPP TS 23.167 │ IMS Emergency Sessions                                     │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ 3GPP TS 23.168 │ Emergency Services Architecture                            │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ 3GPP TS 24.229 │ IP Multimedia Call Control Protocol (SIP/IMS)              │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ 3GPP TS 29.212 │ Policy and Charging Control (Rx/Gx for emergency QoS)      │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ 3GPP TS 29.500 │ 5G Core SBI (NRF, NEF for emergency services)              │
  ├────────────────┼────────────────────────────────────────────────────────────┤
  │ NENA i3        │ Next Generation 9-1-1 (NG911) Architecture                 │
  └────────────────┴────────────────────────────────────────────────────────────┘

  ---

  Summary

  Lesson 10 completes the 3GPP Test Suite's 10-lesson roadmap by implementing the NAT traversal stack (STUN/TURN/ICE) and 3GPP
  Emergency Services. This enables:

  - VoWiFi/VoLTE media path establishment through arbitrary NATs
  - Emergency calls without SIM (limited service / emergency-only registration)
  - Precise location delivery to PSAP via PIDF-LO (geodetic + civic)
  - Standards-compliant implementations of RFC 5389, 8445, 8656, 6442, and TS 24.229

  The modular design follows the project's established patterns: clean header/implementation separation, PCAP export for every
  message, GoogleTest coverage for all encoding/decoding and integration flows, and comprehensive documentation with Wireshark
  analysis guides.
