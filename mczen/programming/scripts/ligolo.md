---
description: Quickly setup and start Ligolo
---

# Ligolo

This script automates setting up and activating the TUN interface, it then adds the IP route. It will then start a http server providing a the download link for the agents and finally start the ligolo proxy server.

```bash
#!/bin/bash

# Function to display usage
usage() {
    echo "Usage: $0 [-p platform] [-i ip_route]"
    echo "  -p: Platform (linux or windows)"
    echo "  -i: IP route (e.g., 172.16.1.0/24)"
    exit 1
}

# Function to get tun0 IP
get_tun0_ip() {
    ip addr show tun0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1
}

# Parse command line arguments
while getopts "p:i:" opt; do
    case $opt in
        p) PLATFORM=$OPTARG ;;
        i) IPROUTE=$OPTARG ;;
        *) usage ;;
    esac
done

# Validate arguments
if [ -z "$PLATFORM" ] || [ -z "$IPROUTE" ]; then
    usage
fi

if [ "$PLATFORM" != "linux" ] && [ "$PLATFORM" != "windows" ]; then
    echo "Error: Platform must be 'linux' or 'windows'"
    exit 1
fi

# Set agent file based on platform
AGENT_FILE="agent"
[ "$PLATFORM" = "windows" ] && AGENT_FILE="agent.exe"

# Setup ligolo interface and route
echo "[+] Setting up ligolo interface..."
sudo ip tuntap add mode tun ligolo || { echo "[-] Failed to create tun interface"; exit 1; }
sudo ip link set ligolo up || { echo "[-] Failed to bring up interface"; exit 1; }
sudo ip route add "$IPROUTE" dev ligolo || { echo "[-] Failed to add route"; exit 1; }
echo "[+] IP route added for $IPROUTE"

# Get tun0 IP
TUN0_IP=$(get_tun0_ip)
if [ -z "$TUN0_IP" ]; then
    echo "[-] Could not determine tun0 IP"
    exit 1
fi

# Start HTTP server in background
echo "[+] Starting HTTP server..."
python3 -m http.server 8000 &
HTTP_PID=$!
echo "[+] File available at http://$TUN0_IP:8000/$AGENT_FILE"

# Start proxy
echo "[+] Starting proxy..."
./proxy -selfcert

# Cleanup
kill $HTTP_PID
```
