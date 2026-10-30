#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Building 3GPP Test Suite ==="
cmake -B "${PROJECT_ROOT}/build" -S "${PROJECT_ROOT}" -DCMAKE_BUILD_TYPE=Debug
cmake --build "${PROJECT_ROOT}/build" -j"$(nproc)"

echo ""
echo "=== Running GoogleTest Suite ==="
"${PROJECT_ROOT}/build/tests/unit_tests"

echo ""
echo "=== Running Lesson 1 Demo App (IP Networking) ==="
(cd "${PROJECT_ROOT}" && "${PROJECT_ROOT}/build/apps/demo_01_ip_echo")

echo ""
echo "=== Running Lesson 2 Demo App (5G SBA TLS 1.3 + HTTP/2) ==="
(cd "${PROJECT_ROOT}" && "${PROJECT_ROOT}/build/apps/demo_02_sba_http2")

echo ""
echo "=== Running Lesson 3 Demo App (VoLTE / VoNR SDP Offer/Answer) ==="
(cd "${PROJECT_ROOT}" && "${PROJECT_ROOT}/build/apps/demo_03_sdp_negotiate")

echo ""
echo "=== Running Lesson 4 Demo App (VoLTE / VoNR SIP IMS Signaling) ==="
(cd "${PROJECT_ROOT}" && "${PROJECT_ROOT}/build/apps/demo_04_sip_volte_call")

echo ""
echo "=== Running Lesson 5 Demo App (VoLTE / VoNR RTP & RTCP Voice Streaming) ==="
(cd "${PROJECT_ROOT}" && "${PROJECT_ROOT}/build/apps/demo_05_rtp_stream")

echo ""
echo "=== Running Lesson 6 Demo App (Diameter S6a LTE EPC Authentication) ==="
(cd "${PROJECT_ROOT}" && "${PROJECT_ROOT}/build/apps/demo_06_diameter_s6a")

echo ""
echo "=== Running Lesson 7 Demo App (LTE Attach / NAS Procedures) ==="
(cd "${PROJECT_ROOT}" && "${PROJECT_ROOT}/build/apps/demo_07_lte_nas")

echo ""
echo "=== Running Lesson 8 Demo App (5G NR Registration / 5GMM & 5GSM) ==="
(cd "${PROJECT_ROOT}" && "${PROJECT_ROOT}/build/apps/demo_08_5g_registration")

echo ""
echo "=== Running Lesson 9 Demo App (LTE & 5G NR RRC Signaling) ==="
(cd "${PROJECT_ROOT}" && "${PROJECT_ROOT}/build/apps/demo_09_rrc_signaling")

echo ""
echo "=== Running Lesson 10 Demo App (STUN/TURN/ICE + Emergency Calling) ==="
(cd "${PROJECT_ROOT}" && "${PROJECT_ROOT}/build/apps/demo_10_stun_ice")

echo ""
echo "=== Verifying Generated PCAPs with tcpdump ==="
echo "--- output_01_ip_echo.pcap ---"
tcpdump -r "${PROJECT_ROOT}/output_01_ip_echo.pcap" -c 2 -nv
echo "--- output_02_sba_http2.pcap ---"
tcpdump -r "${PROJECT_ROOT}/output_02_sba_http2.pcap" -c 4 -nv
echo "--- output_03_sdp_negotiate.pcap ---"
tcpdump -r "${PROJECT_ROOT}/output_03_sdp_negotiate.pcap" -c 2 -nv
echo "--- output_04_sip_volte_call.pcap ---"
tcpdump -r "${PROJECT_ROOT}/output_04_sip_volte_call.pcap" -c 4 -nv
echo "--- output_05_rtp_stream.pcap ---"
tcpdump -r "${PROJECT_ROOT}/output_05_rtp_stream.pcap" -c 4 -nv
echo "--- output_06_diameter_s6a.pcap ---"
tcpdump -r "${PROJECT_ROOT}/output_06_diameter_s6a.pcap" -c 6 -nv
echo "--- output_07_lte_nas.pcap ---"
tcpdump -r "${PROJECT_ROOT}/output_07_lte_nas.pcap" -c 4 -nv
echo "--- output_08_5g_registration.pcap ---"
tcpdump -r "${PROJECT_ROOT}/output_08_5g_registration.pcap" -c 4 -nv
echo "--- output_09_rrc.pcap ---"
tcpdump -r "${PROJECT_ROOT}/output_09_rrc.pcap" -c 5 -nv
echo "--- output_10_stun_ice.pcap ---"
tcpdump -r "${PROJECT_ROOT}/output_10_stun_ice.pcap" -c 2 -nv
echo ""
echo ">>> All checks passed successfully! <<<"
