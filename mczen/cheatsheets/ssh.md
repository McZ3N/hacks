---
description: >-
  SSH, or Secure Shell, is a cryptographic network protocol used to securely
  access and manage remote computers over an unsecured network
---

# SSH

### Add public key

#### Step 1: Generate a Key pair

On your local computer generate a SSH key pair which consists of a public and private key.

```bash
ssh-keygen -t rsa -b 2048
```

#### Step 2: Find the public key

Locate the public key, and copy this key to the ssh server.

```bash
$ cat id_rsa.pub       
ssh-rsa AAAAB3NzjQtIsX8hCkOiq... kali@kali
```

#### Step 3: Copy the key

Copy the key using ssh-copy-id or copy the strings into authorized\_keys file.

```bash
# ssh copy
ssh-copy-id username@serverip

# copy strings
echo 'ssh-rsa AAAAB3NzaC1yc2... kali@kali' >> authorized_keys
```

{% hint style="info" %}
Tips:

* Permissions: Make sure that the `.ssh` directory and the `authorized_keys` file on the server have strict permissions set. This can be done using:

```
chmod 600 ~/.ssh/authorized_keys
```
{% endhint %}

#### Various

```bash
# Convert from hex to ASCI
cat id_rsa | xxd -r -p > file

# Convert from dos to linux
dos2unix id_rsa

# Decrypt with openssl
openssl rsa -in hype_key_encrypted -out hype_key_decrypted

# Force use of ssh-rsa
-o PubkeyAcceptedKeyTypes=ssh-rsa

# Copy files using scp/ssh
scp user@10.10.11.11:/opt/filename /home/kali
```

#### Create ssh key with CA certificate

```bash
# Creating the key
ssh-keygen -t rsa -b 4096 -f keypair
ssh-keygen -s ca-cert -n mczen -I mczen key_pair.pub
ssh -i key_pair mczen@10.10.10.12

# Login with certificate
ssh -o CertificateFile=filename.cert -i keypair mczen@10.10.10.12
```

Good article on SSH-keys: [https://dmuth.medium.com/ssh-at-scale-cas-and-principals-b27edca3a5d](https://dmuth.medium.com/ssh-at-scale-cas-and-principals-b27edca3a5d)
