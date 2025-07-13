---
description: Group Policy Object (GPO) | Management |  Configuration
---

# GPOs

Instead of configuring each computer individually, admins use Group Policy Management Console (GPMC) which enables configuration from a central point. It can modify backgrounds, set security settings or apply configurations.

### <mark style="color:yellow;">Group Policy Object (GPO)</mark>

A Group Policy Object is a collection of policy settings defining appearance and behavior of systems for a group of users or computers.&#x20;

A GPO consists of:

* Group Policy Container (GPC): Represents GPO itself, configuration and settings. Distinguished name contains a GUID unique to GPO.
* Group Policy Template (GPT): Contains settings and configurations as files within the SYSVOL directory on a DC.&#x20;

GPOs are applied through Organizational Units (OUs).&#x20;

### <mark style="color:yellow;">GPO Delegation</mark>

To delegate permissions to link GPOs to a site, domain, or OU, you must have `Modify Permissions` on that site, domain, or OU. By default, only `Domain Administrators` and `Enterprise Administrators` have this permission. Often these rights are delegated to other departmentes like Tech Support. Delegation can be done using `gmpc.msc`.&#x20;

### <mark style="color:yellow;">GPO Links</mark>

Creating a GPO doesnt apply it, its isolated untill we link it to parts in the AD structure like sites, domains, or OUs. Linking activates the rules. With settings that should effect entire network we link the GPO to domain level, marketing would be linked to their OU or site.

#### GPOs are processed in a particular order

* Local
* Site
* Domain
* Organization Units (OUs).

### <mark style="color:yellow;">Example: Enable Firewal</mark>

{% stepper %}
{% step %}
#### Local GPO Application

Computer first applies Local GPO with startup. GPO enable firewall.
{% endstep %}

{% step %}
#### Site GPO Application

If any GPOs linked that encompass this computer those GPOs are appplied. Site-Linked GPOs can modify settings applied by Local GPO.
{% endstep %}

{% step %}
#### Domain GPO Application

After site-linked GPOs, any GPOs linked to the domain and encompassing this computer are applied. Can override Local and Site.
{% endstep %}

{% step %}
#### Domain GPO Applicatio

The GPOs linked to the OU are applied. For example, this GPO disables the Windows Firewall.
{% endstep %}
{% endstepper %}

