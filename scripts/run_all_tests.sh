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
echo "=== Running Lesson 1 Demo App ==="
(cd "${PROJECT_ROOT}" && "${PROJECT_ROOT}/build/apps/demo_01_ip_echo")

echo ""
echo "=== Verifying Generated PCAP with tcpdump ==="
tcpdump -r "${PROJECT_ROOT}/output_01_ip_echo.pcap" -c 5 -nv
echo ""
echo ">>> All checks passed successfully! <<<"
