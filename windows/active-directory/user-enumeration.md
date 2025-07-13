---
description: Retrieving usernames in Active directory for brute forcing or password sprays.
---

# User enumeration

For brute forcing or password spraying we need valid usernames. There are several ways this can be done, from SMB, LDAP, Kerbrute, social engineering or obtained by LLMNR/NBT-NS response poisoning.

### SMB Null session

If you can login without username and password its possible to use various tools to retrieve usernames

{% tabs %}
{% tab title="crackmapexec" %}
```bash
$ crackmapexec smb 172.16.5.5 --users
```
{% endtab %}

{% tab title="enum4linux" %}
```bash
$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```
{% endtab %}

{% tab title="rpcclient" %}
```bash
$ rpcclient -U "" -N 172.16.5.5
```
{% endtab %}
{% endtabs %}

### LDAP Anonymous

Lightweight directory access protocol (LDAP) is a protocol that makes it possible for applications to query user information rapidly. LDAP is protocol to acces data like usernames, passwords, email addresses, printer connections and more static data.

{% tabs %}
{% tab title="ldapsearch" %}
```bash
ldapsearch -D "ldap://10.10.11.41" -x -b "DC=certified,DC=htb" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
```
{% endtab %}

{% tab title="windapsearch" %}
```bash
$ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```
{% endtab %}

{% tab title="ldapdomaindump" %}
```bash
ldapdomaindump -u 'domain.tld\username' -p password -o /tmp dc-ip-address
```
{% endtab %}
{% endtabs %}

An LDAP query typically involves:

* Session connection. The user connects to the server via an LDAP port.&#x20;
* Request. The user submits a query, such as an email lookup, to the server.&#x20;
* Response. The LDAP protocol queries the directory, finds the information, and delivers it to the user.&#x20;
* Completion. The user disconnects from the LDAP port.

<figure><img src="../../.gitbook/assets/image (32).png" alt=""><figcaption><p>source: <a href="https://www.okta.com/">https://www.okta.com/</a></p></figcaption></figure>

### Kerbrute

Kerbrute uses the  [Kerberos Pre-Authentication](kerberos.md). In short user logs on requests the TGT, then receives the TGT from the KDC. User then present the TGT to the DC. If valid it receives a TGS ticket which can be used to acces a service.

```bash
$ ./kerbrute userenum -d viable.zyx /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.11.42
```

### Valid credentials

if you have valid credentials you can get the user with crackmaxexec.

```bash
# crackmapexec
$ sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users

# netexec
$ nxc smb 10.10.11.42 -u olivia -p 'ichliebedich' --users
```

### Password spray

```bash
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

