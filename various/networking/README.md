---
description: A network enables two computers to communicate with each other.
---

# Networking

{% embed url="https://www.youtube.com/watch?ab_channel=Fireship&v=keeqnciDVOo" %}

Internet is based on many subdivid networks. Networking is like the delivery of mail or packages sent by one computer and received by another computer.&#x20;

<table><thead><tr><th width="214">Term</th><th>Description</th></tr></thead><tbody><tr><td>URL</td><td>Uniform Resource Locator which is the address</td></tr><tr><td>FQDN</td><td>Full Qualified Domain Name</td></tr><tr><td>ISP</td><td>Internet Service Provider is like a post office</td></tr></tbody></table>

#### Divide a network in 5 seperate networks

1. Web server in DMZ as clients can connect via internet it should seperated.
2. Workstations shoud be on own network.&#x20;
3. Switch/router on admnistrator network, prevents MitM attacks.
4. IP Phones own network, prevents eavesdropping
5. Printers on own network, print jobs attempt NTLMv2 authentication which can leed to passwords being stolen.

