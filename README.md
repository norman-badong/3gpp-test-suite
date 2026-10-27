# 3GPP Test Suite

[![3GPP Test Suite CI/CD](https://github.com/norman-badong/3gpp-test-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/norman-badong/3gpp-test-suite/actions/workflows/ci.yml)

A training framework and protocol test suite written in **Modern C++ (C++20)** to master, implement, and verify 3GPP cellular and multimedia protocols (4G LTE, 5G NR, IMS VoLTE/VoNR, and EPC/5GC Core).

Designed to run on any POSIX-compliant environment: x86/ARM Linux servers, Raspberry Pi, Android terminals (via Termux/ADB), Docker, or emulators.

---

## Architecture Overview

```
3gpp-test-suite/
├── include/3gpp/
│   ├── common/             # ByteStream, BitBuffer, PcapWriter, Logger
│   ├── ip/                 # Lesson 01: IPv4, IPv6, UDP, TCP headers & sockets
│   ├── sba/                # Lesson 02: TLS 1.3 + HTTP/2 (5G Core SBI)
│   ├── sdp/                # Lesson 03: Session Description Protocol (RFC 4566/3264)
│   ├── sip/                # Lesson 04: Session Initiation Protocol (RFC 3261/3262)
│   ├── rtp/                # Lesson 05: RTP / RTCP Media Engine (RFC 3550/3551)
│   ├── diameter/           # Lesson 06: Diameter Base & 3GPP S6a/Gx (RFC 6733/4006)
│   ├── lte_nas/            # Lesson 07: 4G LTE NAS (TS 24.301 EMM/ESM)
│   ├── nr_nas/             # Lesson 08: 5G NR NAS (TS 24.501 5GMM/5GSM)
│   ├── rrc/                # Lesson 09: LTE & 5G NR RRC (TS 36.331/38.331 ASN.1 APER)
│   └── emergency/          # Lesson 10: STUN/TURN/ICE + SOS (RFC 5389/8445/6442)
├── src/                    # Protocol implementations
├── apps/                   # Standalone runnable demo executables
├── tests/                  # GoogleTest automated unit & integration test suites
└── docs/                   # Deep-dive protocol lesson documentation
```

---

## 10-Lesson Progressive Roadmap

Each lesson follows a strict **Two-Phase Strategy**:
1. **Phase 1 (Simplest Connection First):** Implement the core packet encoder/decoder and a standalone client/server loopback smoke test exporting a `.pcap` trace.
2. **Phase 2 (Advanced Upgrade):** Upgrade to multi-step state machines, authentication algorithms (Milenage, AKA), and full peer interoperability.

| # | Topic | Key Specifications | Status |
| :---: | :--- | :--- | :---: |
| **01** | **IP Networking** | RFC 791 (IPv4), RFC 8200 (IPv6), RFC 768 (UDP), RFC 793 (TCP) | **Completed** |
| **02** | **TLS + HTTP/2** | RFC 8446 (TLS 1.3), RFC 7540 / RFC 9113 (HTTP/2), 3GPP TS 29.500 | **Completed** |
| **03** | **SDP** | RFC 4566, RFC 3264 (Offer/Answer model, AMR/EVS codecs) | **Completed** |
| **04** | **SIP Signaling** | RFC 3261, RFC 3262 (IMS VoLTE/VoNR Call Flow) | **Completed** |
| **05** | **RTP / RTCP** | RFC 3550, RFC 3551 (Voice Media Transport & QoS) | Planned |
| **06** | **Diameter** | RFC 6733, RFC 4006, 3GPP TS 29.272 (S6a, Gx/Gy) | Planned |
| **07** | **LTE Attach / NAS** | 3GPP TS 23.401, TS 24.301 (EMM & ESM) | Planned |
| **08** | **5G Registration** | 3GPP TS 23.502, TS 24.501 (5GMM & 5GSM) | Planned |
| **09** | **LTE / NR RRC** | 3GPP TS 36.331, TS 38.331 (ASN.1 APER Radio Signaling) | Planned |
| **10** | **STUN/ICE + SOS** | RFC 5389, RFC 8445, RFC 6442 (VoWiFi NAT & 3GPP Emergency) | Planned |

---

## Quick Start & Build Guide

### Prerequisites
- Modern C++ compiler supporting C++20 (`g++ >= 11` or `clang++ >= 13`)
- CMake `>= 3.20`
- OpenSSL development headers (`libssl-dev`)
- Wireshark / `tcpdump` (optional, for inspecting generated PCAPs)

### Build
```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
```

### Run All Tests
```bash
./build/tests/unit_tests
```

### Run Lesson 01 Demo
```bash
./build/apps/demo_01_ip_echo
```

Inspect the generated Wireshark trace:
```bash
tcpdump -r output_01_ip_echo.pcap -nvX
```

---

## Continuous Integration & Automated Conformance (CI/CD)

The project includes an enterprise-grade GitHub Actions pipeline ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):
- **Multi-Compiler Matrix:** Automatically compiles and verifies across both **GCC** (`g++`) and **Clang** (`clang++`) in **Debug** and **Release** modes.
- **Protocol Conformance:** Runs all GoogleTest unit suites and verifies zero regressions.
- **PCAP Artifact Publishing:** Runs demo applications, verifies packet headers via `tcpdump`, and uploads Wireshark-compatible PCAP traces as downloadable GitHub artifacts on every push.
