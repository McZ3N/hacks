---
description: ISO/OSI | TCP/IP | Transport | OSI Model | TCIP/IP Mod
---

# Networking Workflow

Two networking models describe the communication and transfer of data from one host to another, called ISO/OSI model and the TCP/IP model.

### <mark style="color:yellow;">OSI Model</mark>

ISO/OSI model is used to describe and define communication between systems using 7 individual layers. It stands for Open Systems Interconnection.

| Layer                                    | Function                                                                                                                                                                                                 |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| <ol start="7"><li>Application</li></ol>  |  Controls input and output of data, provides application functions.                                                                                                                                      |
| <ol start="6"><li>Presentation</li></ol> | Transfer system-dependent presentation of data into a form independent of the application.                                                                                                               |
| <ol start="5"><li>Session</li></ol>      | Controls logical connection between two systems, prevents breakdowns.                                                                                                                                    |
| <ol start="4"><li>Transport</li></ol>    | End-to-end control of transferred data.                                                                                                                                                                  |
| <ol start="3"><li>Network</li></ol>      | Connections are established in circuit-switched networks, and data packets are forwarded in packet-switched networks.                                                                                    |
| <ol start="2"><li>Data Link</li></ol>    | Enable reliable and error-free transmissions on the respective medium                                                                                                                                    |
| <ol><li>Physical </li></ol>              | The transmission techniques used are, for example, electrical signals, optical signals, or electromagnetic waves. Through layer 1, the transmission takes place on wired or wireless transmission lines. |

### <mark style="color:yellow;">TCP/IP Model</mark>

TCP/IP (Transmission Control Protocol/Internet Protocol) is a generic term for many network protocols which are responsible for switching and transport of data packets. The internet is mostly baseed in TCP/IP but ICMP and UDP belongs to the family as wll.

| Layer                                   | Function                                                                                  |
| --------------------------------------- | ----------------------------------------------------------------------------------------- |
| <ol start="4"><li>Application</li></ol> | Allows application to acces the other layers services, defines protocols to exhance data. |
| <ol start="3"><li>Transport</li></ol>   | Provides TCP session and UPD datagram services for layer 4.                               |
| <ol start="2"><li>Internet</li></ol>    | Host addressing, packaging and routing functions.                                         |
| <ol><li>Link</li></ol>                  | Places and receives TCP/IP packets on the network.                                        |

### <mark style="color:yellow;">Packet Transfers</mark>

If we would browse a websites the data is processed layer by layer. Each layer performing assigned functions. It will go through all layers untill data reaches the destinatino servier or device.

<figure><img src="../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

