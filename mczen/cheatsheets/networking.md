# Networking

Ping sweeps

```bash
# fping
fping -asgq 10.10.110.0/24

# Bash
for i in {1..254}; do (ping -c 1 172.19.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;

# Nmap
nmap -sn 10.10.110.0/24
```
