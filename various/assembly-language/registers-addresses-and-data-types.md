---
cover: ../../.gitbook/assets/mohammad-rahmani-8qEB0fTe9Vw-unsplash.jpg
coverY: 0
---

# Registers, Addresses & Data Types

Within Assembly language we will find serveral components we need to understand to help us with debugging and writing assembly code.&#x20;

* Registers
* Memory Addresses
* Address Endianness
* Data Types

### <mark style="color:yellow;">Registers</mark>

Registers are the fastest components in a computer, each CPU core has a set of registers. Registers are limited in size as they can store only a few bytes of data at a time. There are many types of registers, among those are Data Registers and Pointer Registers.

{% tabs %}
{% tab title="Data" %}
Data registers are used for storing instructions/syscall arguments.

rax, rbx, rcx, rdx, r8, r9, r10
{% endtab %}

{% tab title="Pointer" %}
Pointer Registers  are used to store specific important address pointers. A pointer points to a specific location in memory where data is stored

rbp, rsp, rip
{% endtab %}
{% endtabs %}

Having 64-bit registers doesnt mean we have to use 64 bits, we can divide them into smaller sub-registers like 8-bits, 16-bits or 32-bits.&#x20;

Sub-registers&#x20;

| Size in bits | Size in bytes | Name            | Example |
| ------------ | ------------- | --------------- | ------- |
| 8-bit        | 1             | base            | ax      |
| 16-bit       | 2             | base + l        | al      |
| 32-bit       | 4             | base + e prefix | eax     |
| 64-bit       | 8             | base + r prefix | rax     |

And there are more essential registers

<figure><img src="../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

### <mark style="color:yellow;">Memory Addreses</mark>

X86 64 bit processors have 64 bit wide addresses that range from `0x0` to `0xffffffffffffffff`. RAM memory is segmented into various region like stack, heap and other program/kernel regions.&#x20;

{% hint style="info" %}
Sddresses can range from 0 to 2^64 - 1, which is 18,446,744,073,709,551,615 in decimal or 0xFFFFFFFFFFFFFFFF in hexadecimal
{% endhint %}

Each memory has specific read, write and execute permission. When an instruction goes through the instruction cycle the first step is to fetch instruction from the addresss its located at. Type of adress fetching:

{% tabs %}
{% tab title="Immediate" %}
Value is given within instruction: `add 2`
{% endtab %}

{% tab title="Register" %}
Register name that holds the value is given in the instruction: `add rax`
{% endtab %}

{% tab title="Direct" %}
Full ddress given in instruction: `call 0xffffffffba2a22ff`
{% endtab %}

{% tab title="Indirect" %}
Reference points is given in instruction: `call [rax]`
{% endtab %}

{% tab title="Stack" %}
Address is on stop of stack: `add rsp`
{% endtab %}
{% endtabs %}

### <mark style="color:yellow;">Address Endianness</mark>

Address endianness is storing bytes in particular order in memory. There are two different ways of storing multi-byte data in memory, Little-Endian and Big-Endian. In Little-Endian, the least significant byte (LSB) is stored at the lowest memory address, while the most significant  byte (MSB) is stored at the highest memory address. In Big-Endian, the most significant byte (MSB) is stored at the lowest memory address, while the least significant byte (LSB) is stored at the highest memory address.

{% hint style="info" %}
With Little-Endian processors using in Intel/AMD x86, the little-end byte of the address is filled/retrieved first <mark style="color:yellow;">right-to-left</mark>, while with Big-Endian processors, the big-end byte is filled/retrieved first <mark style="color:yellow;">left-to-right</mark>.
{% endhint %}

### <mark style="color:yellow;">Data Types</mark>

X86 architecture supports many types of data sizes, which can be used with various instructions.

| Component           | Length            | Example            |
| ------------------- | ----------------- | ------------------ |
| byte                | 8 bits            | 0xab               |
| word                | 16 bits - 2 bytes | 0xabcd             |
| double word (dword) | 32 bits - 4 bytes | 0xabcdef12         |
| quad word (qword)   | 64 bits - 8 bytes | 0xabcdef1234567890 |

Let’s say you have an **8-bit variable**. If you want to move it into a register, you need to use an **8-bit register**. If you try to use `rax` (which is 64-bit), it won’t work because `rax` expects 64 bits of data, not 8 bits. So instead, you should use `al`, which is the 8-bit portion of `rax`.
