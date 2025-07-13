---
description: >-
  Kerberos is a computer network authentication protocol that verifies the
  identities of users or hosts.
---

# Kerberos

### <mark style="color:yellow;">What is Kerberos</mark>

Kerberos is an authentication protocol, not authorization. So it only identified users who provide a password, but it does not validate to which resources or services this user has access. Once authenticated is can access services. This access is based on tickets, that expire over time.

{% tabs %}
{% tab title="Transport" %}
Kerberos uses UDP or TCP, which sends data in cleartext. Kerberos is responsible for providing encryption and uses ports: UDP/88 and TCP/88.
{% endtab %}

{% tab title="Agents" %}
Agents work together to authenicate in Kerberos.

* Client/User who wants acces to a service.
* AP or Application server which offers service required by user
* KDC (Key Distribution Center) responsible of issuing the tickets, and is installed on the DC (Domain Controller)
{% endtab %}

{% tab title="Encryption keys" %}
There are several structures handled by Kerberos, as tickets. These keys are:

* KDC or krbtgt key derived from krbtgt account as NTLM hash
* User key derived from NTLM hash
* Service key derived from NLTM hash of service owner
* Session key negotiated between user and KDC
* Service session key to be use between user and service
{% endtab %}

{% tab title="PAC" %}
The **PAC** (Privilege Attribute Certificate) structure contains the privileges of the user and it is signed with the KDC key and its included in almost every ticket.
{% endtab %}
{% endtabs %}

<details>

<summary>Messages</summary>

* **KRB\_AS\_REQ**: Used to request the TGT to KDC.
* **KRB\_AS\_REP**: Used to deliver the TGT by KDC.
* **KRB\_TGS\_REQ**: Used to request the TGS to KDC, using the TGT.
* **KRB\_TGS\_REP**: Used to deliver the TGS by KDC.
* **KRB\_AP\_REQ**: Used to authenticate a user against a service, using the TGS.
* **KRB\_AP\_REP**: (Optional) Used by service to identify itself against the user.
* **KRB\_ERROR**: Message to comunicate error conditions.

</details>

### <mark style="color:yellow;">Tickets</mark>

Kerberos works with using tickets. Those tickets are delivered to users to perform serveral actions.&#x20;

* TGS or Ticket Granting Service, used to authenticate against a service, encrypted with service key.
* TGT or Ticket Granting Ticket, is presented to KDC to request tickets or TGSs and is encrypted with KDC key.

<figure><img src="../../.gitbook/assets/image (33).png" alt=""><figcaption><p><a href="https://www.tarlogic.com/blog/how-kerberos-works/">https://www.tarlogic.com/blog/how-kerberos-works/</a></p></figcaption></figure>

### <mark style="color:yellow;">Authentication proces</mark>

{% stepper %}
{% step %}
#### AS\_REQ&#x20;

The user logs on send authenticator, their password is converted to an NTLM hash, which is used to encrypt the TGT ticket. Using current timestamp and cleartexst username. Also called pre-authentication, is not mandatory but enabled by default.
{% endstep %}

{% step %}
#### AS\_REP

KDC generates temporary session key which is used for further exhanges. It will wait for the TGT user requested and contains user info and copy session key which is now protected by the user's key.&#x20;
{% endstep %}

{% step %}
#### TGS\_REQ&#x20;

User received response with TGT protected by KDC's key and session key. Next step is to request a Service Ticket (ST) or TGS ticket with a TGS-REQ message. In this request it contains the name of the service which is the Service Principal Name or SPN. The TGT they just received and the authenticator.&#x20;
{% endstep %}

{% step %}
#### TGS\_REP

The KDC will verify the TGS request by checking the session key in the TGT. After validation  the TGS-REP message is send with a new session key for exchanges between the user and a service. TGS contains name of service, user info from TGT, copy session key.&#x20;
{% endstep %}

{% step %}
#### AP\_REQ

The user decrypts user/service sessions key from the TGS-REP which they can read, unlike the TGS ticket which is encrypted with service secret key. To acces the service it sends the TGS and authenticator which is done by the service using the user/service session key.&#x20;


{% endstep %}

{% step %}
#### AP-REP

Service receives TGS Ticket and authenticator encrypted with users/service session key. A copy of user/service session key is found in the TGS ticket for the service to validate the authenticator with the session key. Service can then read info about user, group memberships and if authentication is succesfull the response is a AP-REP message with ecrypted timestap of extraced session key.&#x20;
{% endstep %}
{% endstepper %}

### <mark style="color:yellow;">Or in 3 phases:</mark>

{% stepper %}
{% step %}
### TGT Request

Authentication Service (AS)
{% endstep %}

{% step %}
### TGS Request

Ticket-Granting Service (TGS)
{% endstep %}

{% step %}
### Service Request

Application Request (AP)
{% endstep %}
{% endstepper %}

### <mark style="color:yellow;">The double hop problem</mark>

If you login to a webserver or SERVER A credentials are authenticated but if that SERVER A needs to acces a database on SERVER B on your behalf it cannot forward them to SERVER B without the right configuration. This can occur working with Evil-WinRM.

### <mark style="color:yellow;">Kerberoasting</mark>

Attack againt service accounts that allows offline password cracking. It needs a valid domain user account and password. A SPN is added when a service registered, its an alias to AD account. Service accounts are utilized with these SPNs but its common to see them tied to User Accounts.&#x20;

{% hint style="info" %}
SPN is for example service/hostname\_or\_FQDN. It could be a web server, network share, SMB or printing service. It identifies services on a network.&#x20;
{% endhint %}

A TGS or Service Ticket requested for all available service is encrypted with a service account's secret key but these are usually 120 chars random passwords, practically impossible to bruteforce. However sometimes there are services executed by user accounts, user accounts passwords are set by humans and more likely to be cracked. SPN accounts use RC4 encryption, but AES is also possible.&#x20;

#### Finding user accounts with SPN

Looking for user accounts exposing a service and thus has a SPN. Either using an ldap filter in a powershell script:

<details>

<summary>find_spn_accounts.ps1</summary>

```powershell
$search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$search.filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
$results = $search.Findall()
foreach($result in $results)
{
    $userEntry = $result.GetDirectoryEntry()
    Write-host "User" 
    Write-Host "===="
    Write-Host $userEntry.name "(" $userEntry.distinguishedName ")"
        Write-host ""
    Write-host "SPNs"
    Write-Host "===="     
    foreach($SPN in $userEntry.servicePrincipalName)
    {
        $SPN       
    }
    Write-host ""
    Write-host ""
}
```

</details>

Or using powerview

```powershell
Import-Module .\PowerView.ps1
Get-DomainUser -SPN
```

### <mark style="color:yellow;">Kerberoasting without account password</mark>

```powershell
# Rubeus attack with /nopreauth
Rubeus.exe kerberoast /nopreauth:john.doe /domain:zencorp.local /spn:MSSQLSvc/SQL01:1433 /nowrap
```

### <mark style="color:yellow;">Kerberos Delegations</mark>

Kerberos allows a user to authenticate to a services and use it. Kerberos delegation enables that service to authenticate to another services as that user.&#x20;

* **Unconstrained Delegation**: Allows a service to impersonate a user when accessing another service which is very dangerous. An administrator with `SeEnableDelegationPrivilege` can set this on a account, a service account cannot modify itself to add this option.&#x20;
* **Constrained Delegation**: Here the service has the right to impersonate to a user based on a list of services like a Webserver can only relay authentication to DB Server for SQL/HOST/CFS.
* **Resource-Based Constrained Delegation**: This delegation is based on resource level, any account on a rusted list has the right to delegate authentication to access the resource. The resource has the right to modify its trusted list. Any service account can modify the trusted list to allow account to delegate authentication to themselves.&#x20;

| Type                                  | Description                                                                    | Mechanism                                                   |
| ------------------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------- |
| Unconstrained Delegation              | Allows a service to request access to any other service on behalf of the user. | Service can request access to any service on behalf of user |
| Constrained Delegation                | Limits the services a delegate can request access to on behalf of the user.    | Limited to pre-configured service list and uses (S4U2Proxy) |
| Resource-Based Constrained Delegation | Allows the resource owner to control which services can delegate access to it. | Resource decides which accounts can delegate to it.         |

### <mark style="color:yellow;">S4U2Proxy</mark>

Kerberos extension that allows a service to impersonate a user when requesting acces to another resource. S4U2Proxy is used for **delegation**, where a service acts on behalf of a user.

{% hint style="info" %}
1. Service A has a TGS ticket for user X,
2. Service A need to acces other resource service B on behalf of user X.&#x20;
3. Service A sends request to DC, includes copy user X TGS ticket.
4. DC check if service A has right to delegate user X credentials to service B.
5. Service A plus User X have valid ticket for service B.
{% endhint %}

### <mark style="color:yellow;">S4U2Self</mark>

When a user authenticates using NTLM, not kerberos it doesn't get a TGS ticket and so the S4U2Proxy can't act on behalf. S4U2Self is kerberos extension that allows the service to request a TGS ticket for itself on behalf of the user.&#x20;

{% hint style="info" %}
1. User authenticates using NTLM.
2. Services requests a TGS Ticket (S4U2Self)
3. Services uses S4U2Proxy
{% endhint %}

### <mark style="color:yellow;">Printer Bug</mark>

Printer Bug is a vulnerability in the MS-RPRN protocol which is used for managing print jobs and printers. This bug can trick a server into authenticating to another machine over SMB.

{% hint style="info" %}
1. Using printer bug, force a server like DC to a machine attacker controls. It happens by connecting to print service using MS-RPRN methods.&#x20;
2. That server sends TGT or ST to attackers machine. If its DC contains full domain admin privileges.
3. Full acces for DCSynce and such.&#x20;
{% endhint %}

### <mark style="color:yellow;">Unconstrained Delegation - Users</mark>

Need to compromise an account with TRUSTED\_FOR\_DELEGATION and GenericWrite to update its SPN list.&#x20;

{% hint style="info" %}
1. Create a fake DNS record that points to attacker's machine. DNS record will be a fake computer in the AD.
2. Assign the **CIFS SPN (CIFS/our\_dns\_record)** to a compromised account.
3. When a victim tries to connect to the fake computer (eg SMB). It will ship a copy of its TGT in its TGS ticket
4. This TGS ticket will be sent to attacker IP which was sset in DNS record. We can then extract the TGT and use it.
{% endhint %}

## <mark style="color:yellow;">Constrained Delegation</mark>&#x20;

Unlike unconstrained, constrained delegation acts on behalf of users but only to specific services that have been allowed. Its more secure and restrictive. For a example a user logging in to a financial application where the backend database server applies permissions instead of the account permissions .

> A service account needs Kerberos-constrained delegation enabled so a user's ticket is used to acces a database.&#x20;

A TGS Ticket contains an unencrypted part which contains the SPN of the request service. This can be modified and the request will still be valid. In constrained delegation. Using S4U2Proxy we can obtain valid TGS tickets on behalf of users. This way we a valid TGS ticket is obtained for a SPN which is for a service account.&#x20;

{% hint style="info" %}
If a service account exposes serval services, its possible to modify the SPN to access a different service like CIFS or SPOOLER.
{% endhint %}

#### Impersonate any user

If the constrained delegation allows protocol transition we can impersonate to be anyone. Using S4U2Self which allows a service to obtain a forwardable service ticket to itself on behalf of any user.&#x20;

### <mark style="color:yellow;">Resource-based constrained delegation (RBCD)</mark>

RBCD is delegation based allowing delegation settigns to be configured on the target service instead of the service account being used to access resources.&#x20;

{% hint style="info" %}
1. In RBCD, delegation settings are managed on the **backend service** (the target service that resources are being accessed from.&#x20;
2. Instead of an **allowed list of SPNs**, RBCD relies on **security descriptors**, which define permissions for specific users or services to act on behalf of other users.
3. The `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of the backend service holds the **security descriptor** which lists which services are allowed to request tickets for a user.
4. KDC checks the attribute, if it matches the KDC grants access.
{% endhint %}

### <mark style="color:yellow;">Silver Ticket</mark>

Every machine account has an NTLM hash, the hash of the computer represented as SYSTEM$. The NTLM hash acts as a pre-shared key or PSK between domain and workstations. The PSK is used to sign TGS. This ticket is less powerfull than Golden as it can only access that single machine.&#x20;

{% hint style="info" %}
1. Compromise a Service Account by gettings its NTLM hash or encryption key.&#x20;
2. With knowledge of secret create a fake PAC, claiming to be a domain admin.
3. Encrypt the forged ticket with the stolen service account secret.
4. The service will accept the forged TGS ticket because it can decrypt it using its own password and will read contents of PAC.
{% endhint %}

To forge a silver ticket you need: NTLM password for Service account or Machine account, SID of domain, target host, SPN, arbitrary username and group information.&#x20;

### <mark style="color:yellow;">Sacrificial Processes</mark>

A pass the ticket attack does not touch LSASS which is Sekurlsa::LogonPasswords. When attacking kerberos a failure to create a sacrificial process can result in taking down a service. This happens because of overwiting an existing logon session and require a service restart or machine reboot when it loses its ticket. &#x20;

{% hint style="info" %}
A Sacrificial Process creates a new Logon Session, isolating manipulated tickets and preventing impact on critical sessions, so its safer than causing outage.&#x20;
{% endhint %}
