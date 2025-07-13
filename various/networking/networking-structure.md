---
description: Network types | Networking Topologies | Proxies
---

# Networking Structure

Each network is structured differently and therefor many type and topologies have been invented so we can categorize these networks.

| Term                                | Definition                                |
| ----------------------------------- | ----------------------------------------- |
| Wide Area Network (WAN)             | Internet                                  |
| Local Arean Network (LAN)           | Internal Networks like: Home              |
| Wireless Local Arean Network (WLAN) | Internet Networks over Wi-Fi              |
| Virtual Private Network (VPN)       | Connect multiple network sites to one LAN |

#### WAN

Networking equipment often have a WAN and LAN address. WAN is the address used for the internet, a WAN is just a large number of LANs joined together., although its possible to see Internal WAN in large companies which we call Internal WAN or Intranet.

#### LAN / WLAN

LANS or Local Area Network and WLAN or Wireless Area Network assign IP's for local use .

#### VPN

There are three main types Virtual Private Networks (VPN).

{% tabs %}
{% tab title="Site-To-Site VPN" %}
Both the client and server are Network Devices, typically either Routers or Firewalls. Most used to join company networks over internet as if they were local.
{% endtab %}

{% tab title="Remote Acces VPN" %}
A client's computer creates virtual interface as if it's on a clients network. An example is OpenVPN. It can also be a Split-Tunnel VPN where there is no outoing connection to the internet.&#x20;
{% endtab %}

{% tab title="SSL VPN" %}
This is essentially a VPN that is done within our web browser. It will provide secure remote access to a private network through a web browser.
{% endtab %}
{% endtabs %}

### <mark style="color:yellow;">Networking Topologies</mark>

A network topology is an arrangement and physical or logical connection of devices in an network. Computers are hosts such as clients and servers. But also include components like switches, bridges and routers.&#x20;

Network topology in 3 areas:

| Wired Connections    | Wireless Connections |
| -------------------- | -------------------- |
| Coaxial cabling      | Wi-Fi                |
| Glass fiber cabling  | Cellular             |
| Twisted-pair cabling | Satellite            |

Nodes - Network Interface Controller (NICs) like: repeaters, hubs, bridges, switches, routers, modems, gateways, firewall.

### <mark style="color:yellow;">Proxies</mark>

A proxy is when a device or service sits in the middle of a connection and acts a mediator. It can inspect the contents of the traffic, like Burp.&#x20;

{% tabs %}
{% tab title="Dedicated Proxy" %}
A dedicated or forward proxy carries out request a client makes. In a corporated network a computer no have acces to the internet but only when it uses a proxy.
{% endtab %}

{% tab title="Reverse Proxy" %}
Reverse proxies filters incoming requests, it will listen to an address and forwards it to a closed-off network, like CloudFlare.&#x20;
{% endtab %}

{% tab title="Transparent proxy" %}
With a transparent proxy, the client doesn't know about its existence.&#x20;
{% endtab %}
{% endtabs %}



