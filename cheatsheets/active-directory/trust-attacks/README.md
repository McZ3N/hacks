---
description: Active Directory Trust Attacks | Domain & Forest Trusts
---

# Trust Attacks

There are intra-forest which allow for communication and resource sharing between multiple domains within a single forest. Cross forest trust works across domains in dfferent forests. So intra is within and cross is across domains.&#x20;

* A **domain** is a collection of objects (e.g., users, groups, computers) that share the same directory database.
* A **tree** is a group of domains that share a contiguous namespace (e.g., `example.com` and `sub.example.com`).
* A forest can contain multiple domain trees, even with disjoint namespaces (e.g., `example.com` and `anotherdomain.com`).

### <mark style="color:yellow;">Enumerating Domain & Forest Trusts</mark>

Using the Activedirectory module, `Import-Module activedirectory`:

#### Look for possible trust relationships

```sh
Get-ADTrust -Filter *
```

#### With powerview

```sh
# Enum trust
Get-DomainTrust

# Enumerate all trusts for every domain that is uncovered
Get-DomainTrustMapping
```

#### **Types of Trusts**

1. **Parent-Child:** Built-in trust between a parent and child domain within a forest.
2. **Tree-Root:** Connects the root domains of different trees within a forest.
3. **External:** Links domains across separate forests for resource access.
4. **Forest Trust:** Trust between two entire forests for broad access.
5. **Shortcut (Cross-Link):** Reduces authentication steps between distant domains.
6. **Realm Trust:** Connects a Windows domain to a non-Windows Kerberos realm.

### In a nutshell

What does a forest look like. Forest, trees and domains.

```
Forest: Microsoft Corporation
├── Tree 1: microsoft.com
│   ├── microsoft.com (root)
│   ├── na.microsoft.com
│   └── eu.microsoft.com
└── Tree 2: xbox.com
    ├── xbox.com (root)
    └── live.xbox.com
```

Then there are Parent-Childs

```
painters.htb (Parent Domain)
└── sales.painters.htb (Child Domain)
    └── dev.sales.painters.htb (Grandchild Domain)
```

And then Intra-Forest&#x20;

```
Example (Intra-Forest):
Forest: company.com
├── company.com (root)
├── sales.company.com
└── it.company.com
```

Cross-Forest

```
Example (Cross-Forest):
Forest 1: company.com           Forest 2: partner.com
├── company.com                 ├── partner.com
└── sales.company.com          └── dev.partner.com
        ↑________________________↑
        (Cross-Forest Trust)
```

