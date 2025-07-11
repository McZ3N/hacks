---
description: '| ACL | DACL | ACL | ACE | AD | Active Directory'
---

# DACL

A discretionary access control list (DACL) identifies the trustees that are allowed or denied access to a securable object. When a process tries to access a securable object, the system checks the ACEs in the object's DACL to determine whether to grant access to it.

{% embed url="https://www.youtube.com/watch?ab_channel=NetworkEncyclopedia&v=Vo4u_5c7gG0" %}

ACE's or access control entries describe allowed and denied permssions for a principal, where a principal is an entity which can be authenticated by a system or network like users, computer accounts, services, groups and processes against a securable object (user, group, computer, container, organizational unit (OU), GPO.

The four general categories of access control policies are

* `Discretionary access control` (`DAC`)
* `Mandatory access control` (`MAC`)
* `Role-based access control` (`RBAC`)
* `Attribute-based access control` (`ABAC`)

{% hint style="info" %}
Windows is an example of a `DAC` operating system, which utilizes `Discretionary access control lists` (`DACLs`). DAC controls access based on the requestor's identity and access rules stating what requestors are (or are not) allowed to do
{% endhint %}

### <mark style="color:yellow;">Security Descriptors</mark>

In Windows, every object like files/dirs/processes has a `security descriptor` data structure that defines what actions a user can perform on a object. It contains:

* Revision number: SRM (Security Reference Monitor) version of security model used to create descriptor.
* Control Flags: Optional modifiers that define behaviour of security descriptor.
* Owner SID: Objects owner SID
* Group SID: Primary's group SID
* Discretionary access control list (DACL): Who has access tot the object.
* System access control list (SACL): Which operations by which users should be logged in audit log.

### <mark style="color:yellow;">Discretionary Access Control List (DACL)</mark>

{% hint style="info" %}
A **DACL** (Discretionary Access Control List) is a list of permissions attached to a securable object in Windows. It specifies **who can access the object** and **what actions they are allowed to perform** (e.g., read, write, execute).
{% endhint %}

DACLs are lists made of ACEs that identify users and groups that that are allowed or denied access on an object. When misconfigured, ACEs can be abused to operate lateral movement or privilege escalation within an AD domain.

{% embed url="https://www.thehacker.recipes/ad/movement/dacl/" %}

### <mark style="color:yellow;">ACEs</mark>

An **ACE** includes a set of user rights and a Security Identifier (SID) that specifies the principal to whom these rights are granted, denied, or audited.

| Aspect         | Security principal                                        | Access Control Entry (ACE)                                        |
| -------------- | --------------------------------------------------------- | ----------------------------------------------------------------- |
| Definition     | A user, group or system entity that can have permissions. | A specific rule that defines permissions for a securit principal. |
| Purpose        | Identifies who can access a resource.                     | Specifies what actions the identified entity can perform.         |
| Examples       | User: jdoe, Group: Administrator, Identity: System        | User jdoe can read and write a file.                              |
| Where?         | As entity in system or AD.                                | Part of DACL or SACL.                                             |
| Key identifier | Security Identifier (SID).                                | Linked to a security principal and permission type.               |

In a DACL there can be 9 types of ACEs but there are four main types of `ACEs` which are important to understand.

| ACE                                                                                                                          | Description                                                                                                                                           |
| ---------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| [ACCESS\_ALLOWED\_ACE](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_ace)                | Allows security principal to access AD object such as user account/group. It specifies read, write or modify.                                         |
| [ACCESS\_ALLOWED\_OBJECT\_ACE](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace) | Grants access the object itself and any child objects it contain. Grants security principal access to object and child objects.                       |
| [ACCESS\_DENIED\_ACE](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_denied_ace)                  | Denies a security principal access to an AD object, like a user or group. It cannot read, write or modify that object.                                |
| [ACCESS\_DENIED\_OBJECT\_ACE](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_denied_object_ace)   | Applied to object and restricts access to that object and child objects. It prevents a security principal from accessing an object and child objects. |

An ace is made of four components:

* Security identifier or SID
* The type of ACE (allowed or denied)
* Set of flags specifying child containers inheret the ACE
* 32-bit access mask, defines rights.

We can use ACE entries for furthers acces. We can use bloodhound to enumerate these ACEs and will find common permissions like:

* `ForceChangePassword` abused with `Set-DomainUserPassword`
* `Add Members` abused with `Add-DomainGroupMember`
* `GenericAll` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
* `GenericWrite` abused with `Set-DomainObject`
* `WriteOwner` abused with `Set-DomainObjectOwner`
* `WriteDACL` abused with `Add-DomainObjectACL`
* `AllExtendedRights` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
* `Addself` abused with `Add-DomainGroupMember`

### <mark style="color:yellow;">Logon Scripts</mark>

Administrators use logon scripts to automate tasks or configurations when logging into the domain. Things like mapping/unmapping network drives, auditing and reporting, gathering information and enviromen customization.

{% hint style="info" %}
Windows stores `logon scripts` in the `scripts` folder within the `SYSVOL` network share or at: %systemroot%\SYSVOL\sysvol. SYSVOL also stores domain policies and GPOs.
{% endhint %}

The scriptPath attribute specifies the path to a logon script when a user logs into the domain. Supported script types are:

* Batch files like `.bat` or `.cmd`
* Executables like `.exe`
* Languages like `.vbs` and `.js`

ScriptPath does not support powershell.

### <mark style="color:yellow;">SPN Jacking</mark>

This attack combines Constrained delegation abuse and DACL abuse. With constrained delegations its possible to authenticate to services from server A, and even different services on that server. But authenticating to server B is not possible. This is because server B is not listed in the spn.

SPN jacking uses WriteSPN rights to remove the service/serverA from serverA and configures it into the target machine like serverB as service/serverA

{% hint style="info" %}
Ghost SPN-Jacking targets scenarios where an SPN, previously associated with a computer or service account, is either no longer in use, the're called Orphaned SPNs.

\
Live SPN-Jacking requires active manipulation of SPNs in use of the network.
{% endhint %}
