---
description: Lightweight Directory Access Protocol | AD | User information | User accounts
---

# LDAP

{% embed url="https://www.youtube.com/watch?ab_channel=EyeonTech&v=SK8Yw-CiRHk" %}

Lightweight Directory Access Protocol (LDAP) is an integral part of Active Directory (AD). Latest version is [RCF 4511](https://tools.ietf.org/html/rfc4511). LDAP is open source and used for authentication against directory services such as Active Directory.

LDAP is the language that applications use to communicate with services like Active Directory and with other server that provide directory services as well. LDAP lets systems in the network talk with the AD.

<figure><img src="../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

### <mark style="color:yellow;">AD LDAP Authentication</mark>

There are 2 types of LDAP authentication:

1. **Simple authentication** including anonymous authentication, unauthenticated authentication, and username/password authentication.  It will create a BIND request to LDAP server.
2. **SASL authentication**. SASL using authentication services like Kerberos to bind to the LDAP server. The LDAP protocol sends LDAP message which starts challenge and response messages.&#x20;

{% hint style="info" %}
LDAP authentication messages are sent in cleartext.
{% endhint %}

### <mark style="color:yellow;">LDAP queries</mark>

Communicating with directory services using LDAP is done with queries.&#x20;

| Query                                         | Result                             |
| --------------------------------------------- | ---------------------------------- |
| (objectCategory=computer)                     | find all workstations in a network |
| ((&(objectCategory=person)(objectClass=user)) | searches for all users             |
| (objectClass=group)                           | searches for all groups            |

More queries: [computers](https://ldapwiki.com/wiki/Wiki.jsp?page=Active%20Directory%20Computer%20Related%20LDAP%20Query), [users](https://ldapwiki.com/wiki/Wiki.jsp?page=Active%20Directory%20User%20Related%20Searches), [groups](https://ldapwiki.com/wiki/Wiki.jsp?page=Active%20Directory%20Group%20Related%20Searches).

### <mark style="color:yellow;">Example queries</mark>

Find disabled users

```powershell
 Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' -Properties * | select samaccountname,useraccountcontrol
```

Find out how many users, computers and groups

```powershell
PS C:\Users\mczen> (Get-ADUser -Filter *).Count
877
PS C:\Users\mczen> (Get-ADComputer -Filter *).Count
7
PS C:\Users\mczen> (Get-ADGroup -Filter *).Count
90

# Or specify a group
(Get-ADGroupMember -Identity "IT").Count
```

## Powershell Filters

Filters in PowerShell allows us to get better output and retreive data we are looking for. It can be used to narrow down specific data in large result.&#x20;

This would filter out all Microsoft software making the list of search results a lot smaller.&#x20;

```powershell
PS C:\zen> get-ciminstance win32_product -Filter "NOT Vendor like '%Microsoft%'" | fl

IdentifyingNumber : {748D3A12-9B82-4B08-A0FF-CFDE83612E87}
Name              : VMware Tools
Vendor            : VMware, Inc.
Version           : 10.3.2.9925305
Caption           : VMware Tools
```

<details>

<summary>Operators</summary>

```
Meaning
-eq	        Equal to
-le	        Less than or equal to
-ge	        Greater than or equal to
-ne	        Not equal to
-lt	        Less than
-gt	        Greater than
-approx	        Approximately equal to
-bor	        Bitwise OR
-band	        Bitwise AND
-recursivematch	Recursive match
-like	        Like
-notlike	Not like
-and	        Boolean AND
-or	        Boolean OR
-not	        Boolean NOT
```

</details>

Find users with `DoesNotRequirePreAuth` who's accounts can be ASREPRoasted.

```powershell
# Administrative groups
Get-ADUser -Filter {adminCount -eq '1' -and DoesNotRequirePreAuth -eq 'True'}

# All users
Get-ADUser -Filter {DoesNotRequirePreAuth -eq 'True'}

# Get group members
Get-ADGroupMember -Identity "Protected Users"
```

Get info about a host

```powershell
# Get basic information
Get-ADComputer WS01

# Get detailed information, including operating system, last logon time, etc.
Get-ADComputer WS01 -Properties *

# Get specific properties
Get-ADComputer WS01 -Properties OperatingSystem, LastLogonDate, Description
```

## LDAP Search Filters

The `-LDAPFilter` enables us to use LDAP search filters which syntax is defined here: [https://datatracker.ietf.org/doc/html/rfc4515](https://datatracker.ietf.org/doc/html/rfc4515)

LDAP filters must have 1 or more criteria, when using more we use AND or OR to concatenate.&#x20;

| Operator | Function |
| -------- | -------- |
| &        | and      |
| \|       | or       |
| !        | not      |

### <mark style="color:yellow;">Search criteria</mark>

When using an LDAP search filter we need to specifiy rules, like `(displayName=mczen)`.&#x20;

<table><thead><tr><th width="156">Critera</th><th width="175">Rule</th><th>Example</th></tr></thead><tbody><tr><td>Equal to</td><td>(attribute=123)</td><td>(&#x26;(objectclass=user)(displayName=Smith)</td></tr><tr><td>Not equal to</td><td>(!(attribute=123))</td><td>!objectClass=group)</td></tr><tr><td>Present</td><td>(attribute=*)</td><td>(department=*)</td></tr></tbody></table>

More attributes [https://docs.bmc.com/docs/fpsc121/ldap-attributes-and-associated-fields-495323340.html](https://docs.bmc.com/docs/fpsc121/ldap-attributes-and-associated-fields-495323340.html)

### <mark style="color:yellow;">Object Identifiers (OIDs)</mark>

Object Identifiers (OIDs) are unique identifiers used to name objects. We can use machting rule OIDs with LDAP filters, found [here](https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx). This query will return all administratively disabled user accounts, or [ACCOUNTDISABLE (2)](https://ldapwiki.com/wiki/Wiki.jsp?page=ACCOUNTDISABLE) with matching rule: [1.2.840.113556.1.4.803](https://ldapwiki.com/wiki/Wiki.jsp?page=1.2.840.113556.1.4.803)

```powershell
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2)' | select name
```

* `1.2.840.113556.1.4.803` is the Object Identifier (OID) for a bitwise AND operation.
* `:=2` checks if account is disbabled

#### Find all groups

```powershell
Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' | select Name
```

* **`1.2.840.113556.1.4.1941`** This OID find all groups that the user is a member off
* **`:=`**`:` Specifies the equality match.

#### LDAP Queriy - Description Field

```powershell
Get-ADUser -Properties * -LDAPFilter '(&(objectCategory=user)(description=*))' | select samaccountname,description
```

* `objectCategory=user`: Ensures that only user objects are retrieved.
* `description=*`: Ensures that only users with a non-empty description field are retrieved.

#### **LDAP Query - Find Trusted Users**

This filter "`(userAccountControl:1.2.840.113556.1.4.803:=524288)`" can be used to find all users or computers marked as `trusted for delegation`, or unconstrained delegation. Trusted users can act on behalf of other users in AD.

```powershell
# Get users
Get-ADUser -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select Name,memberof, servicePrincipalName,TrustedForDelegation | fl

# Get computers
Get-ADComputer -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select DistinguishedName,servicePrincipalName,TrustedForDelegation | fl
```

* `1.2.840.113556.1.4.803` is the Object Identifier (OID) for a bitwise AND operation
* `:=524288` checks if the bit corresponding to the `TRUSTED_FOR_DELEGATION`

#### **LDAP Query - Users With Blank Password**

```powershell
Get-AdUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))(adminCount=1)' -Properties * | select name,memberof | fl
```

* `(userAccountControl:1.2.840.113556.1.4.803:=32)`: Checks if the bit corresponding to the `PASSWD_NOTREQD` flag is set in the `userAccountControl` attribute. This indicates that a password is not required for the account.

### <mark style="color:yellow;">Recursive Match</mark>

With RecursiveMatch we dcan find all of the groups an AD user is part of, both direct and inderect group memberships?

```powershell
# Won't show nested groups
Get-ADUser -Identity harry.jones -Properties * | select memberof | ft -Wrap

# Will show all groups, including nested
 Get-ADGroup -Filter 'member -RecursiveMatch "CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL"' | select name
```

### <mark style="color:yellow;">SearchBase and SearchScope Parameters</mark>

`SearchScope` allows us to define how deep into the OU hierarchy we would like to search. This parameter has three levels:&#x20;

<table data-header-hidden><thead><tr><th width="138">Name</th><th width="96">Level</th><th>Description</th></tr></thead><tbody><tr><td>Base</td><td>0</td><td>The object is specified as the <code>SearchBase</code>. Base scope only looks at the OU itself, not at users within.</td></tr><tr><td>OneLevel</td><td>1</td><td>Searches for objects in the container defined by the <code>SearchBase</code> but not in any sub-containers. Or 1 level deep.</td></tr><tr><td>SubTree</td><td>2</td><td>Entire subtree, including all levels of sub-containers and their children. Recursively all the way down the AD hierarchy.</td></tr></tbody></table>

#### Searchscope Base

```powershell
# Count all AD users
PS C:\zen> (Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -Filter *).count
970

# Empty output
PS C:\zen> Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Base -Filter *
PS C:\zen>

# Search Base OU object
PS C:\zen> Get-ADObject -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Base -Filter *

DistinguishedName                      Name      ObjectClass        ObjectGUID
-----------------                      ----      -----------        ----------
OU=Employees,DC=INLANEFREIGHT,DC=LOCAL Employees organizationalUnit 34f42767-8a2e-493f-afc6-556bdc0b1087
```

#### Searchscope OneLevel

```powershell
# We get one user returned to us
PS C:\htb> Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope OneLevel -Filter *
```

#### Searchscope Subtree

```powershell
# Will count all objects
PS C:\zen> (Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Subtree -Filter *).count

# Or count all employees in IT
(Get-ADUser -SearchBase "OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Subtree -Filter *).count
```

### <mark style="color:yellow;">PowerView</mark>

PowerView is a PowerShell tool for enumerationg AD's and gathering network information. It provides a set of functions to explore Active Directory, identify users, computers, and groups, and analyze their relationships. Use by `Import-Module .\PowerView.ps1`.

```powershell
# Show useraccountcontrol attributes.
Get-DomainUser * -AdminCount | select samaccountname,useraccountcontrol

# Find user in OU writers
Get-ADUser -SearchBase "OU=Writers,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -Filter * | Select-Object SamAccountName
```

### <mark style="color:yellow;">DS Tools</mark>

List the SAM account names of users whose passwords are set to never expire

```
dsquery user "OU=Employees,DC=inlanefreight,DC=local" -name * -scope subtree -limit 0 | dsget user -samid -
pwdneverexpires | findstr /V no
```

### <mark style="color:yellow;">**Windows Management Instrumentation (WMI)**</mark>

```
Get-WmiObject -Class win32_group -Filter "Domain='INLANEFREIGHT'" | Select Caption,Name
```

## LDAP Anonymous Bind

LDAP anonymous binds allow unauthenticated attackers to retrieve information from the domain, this can be used to list users, groups, computers, account attributes and password policies.&#x20;

{% hint style="info" %}
A anonymous bind is a request where the username and password fields are left empty.
{% endhint %}

We can use python to interact LDAP:

```bash
Python 3.8.5 (default, Aug  2 2020, 15:09:07) 
[GCC 10.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from ldap3 import *
>>> s = Server('10.129.1.207',get_info = ALL)
>>> c =  Connection(s, '', '')
>>> c.bind()
True
>>> s.info
```

### <mark style="color:yellow;">Ldapsearch</mark>

We can use tools suchas windapsearch and ldapsearch to enumerate a domain.&#x20;

```bash
# ldapsearch
ldapsearch -H ldap://10.129.1.111 -x -b "dc=zencorp,dc=local"

# Info
python3 ldapsearch-ad.py -l 10.129.1.207 -t info
```

### <mark style="color:yellow;">Windapsearch</mark>

```bash
# Check for bind
python3 windapsearch.py --dc-ip 10.129.1.111 -u "" --functionality

# Get domain users
python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -U

# Get domain computers
python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -C

# Search for OU by user
python3 windapsearch.py --dc-ip 10.129.42.188 -u "" -s "john doe"

# Show groups
python3 windapsearch.py --dc-ip 10.129.42.188 -u "" -G

# Unconstrained delegation
python3 windapsearch.py --dc-ip 10.129.42.188 -u "" -U --unconstrained-users
```

## Credentialed Enumeration

When having domain credentials we get retrieve all kinds for information from LDAP.&#x20;

```bash
python3 windapsearch.py --dc-ip 10.129.1.207 -u zencorpo\\john.doe --da
```

Of checking for users with unconstrained delegations.

```bash
python3 windapsearch.py --dc-ip 10.129.1.207 -d zencorp.local -u zencorp\\john.doe --unconstrained-users
```

Or using ldapsearch

```bash
# Check password policy
python3 ldapsearch-ad.py -l 10.129.1.207 -d zencorp -u john.doe -p pass123 -t pass-pols

# Check for Kerberoastable users
python3 ldapsearch-ad.py -l 10.129.1.207 -d zencorp -u john.doe -p pass123 -t kerberoast | grep servicePrincipalName

# Check ofr ASREPRoastable users
python3 ldapsearch-ad.py -l 10.129.1.207 -d zencorp -u john.doe -p pass123 -t asreproast
```

If we want to find users with `smartcard_required` attribute set we can use the LDAP filter `(userAccountControl:1.2.840.113556.1.4.803:=262144)`.&#x20;

```bash
python3 ldapsearch-ad.py -l 10.129.42.188 -d zencorp -u john doe -p pass123 -t search -s "(userAccountControl:1.2.840.113556.1.4.803:=262144)"
```

* `userAccountControl`: LDAP attribute being queried
* `:1.2.840.113556.1.4.803:` LDAP Matching Rule OID for bitwise matching
* `:=`: **bitwise AND** operation
* `262144`: corresponds to the **SMARTCARD\_REQUIRED** flag

<figure><img src="../../.gitbook/assets/image (13).png" alt=""><figcaption><p>Properties <a href="https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties">here</a></p></figcaption></figure>
