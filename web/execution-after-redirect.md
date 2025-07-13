---
description: >-
  An attack where an attacker ignores redirects and retrieves sensitive content
  intended for authenticated users
---

# Execution After Redirect

EAR

Execution After Redirect (EAR) is an attack where an attacker ignores redirects and retrieves sensitive content intended for authenticated users. A successful EAR exploit can lead to complete compromise of the application.

```php
<?php if (!$loggedin) {
     print "<script>window.location = '/login';</script>\n\n"; 
} ?>
<h1>Admin</h1>
<a href=/mu>Manage Users</a><br />
<a href=/ud>Update Database Settings</a>
```

This checks if the parameter `loggedin` is true. If its not true it uses javascript to redirect to the login page. However by disabling javascript in the browser the same request is repeated without following the JavaScript redirect and the “Admin” section is accessible without authentication.

{% hint style="info" %}
This vulnerabilty can be found in [https://www.hackthebox.com/machines/previse](https://www.hackthebox.com/machines/previse)
{% endhint %}

## Example

Using the previse machine we will demonstrate the EAR vulnerbality. For this we are going to use Burp which can intercept responses.

<figure><img src="../.gitbook/assets/image (52).png" alt=""><figcaption><p>Check box at "Intercept responses..."</p></figcaption></figure>

Using this we visit 10.10.11.104/files.php en change the response from 302 to 200. And we get content back which us normally only for authenticated user.

<figure><img src="../.gitbook/assets/image (54).png" alt=""><figcaption></figcaption></figure>

Using Burps match/replace we can automatically change the 302's to a 200 code.&#x20;

<figure><img src="../.gitbook/assets/image (55).png" alt=""><figcaption></figcaption></figure>

Using this we were able to reach the account page and create a user and a login.
