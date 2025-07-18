---
description: The design and operational structure of computers.
cover: ../../.gitbook/assets/ella-don-k1Wiqp6jyy0-unsplash.jpg
coverY: 0
---

# Computer Architecture

Surprisingly the modern day architecture of computers are still built on the [Von Neumann Architecture](https://en.wikipedia.org/wiki/Von_Neumann_architecture) originating from 1945. This architecture executes machine code and consists of:

* Central Processing Unit or CPU
* Memory Unit
* Input/Output Devices like keyboard or display

The CPU is made of 3 main components:

* Control Unit or CU
* Arithmetic/Logic Unit (ALU)
* Registers

### <mark style="color:yellow;">Memory</mark>

All temporary data and instructions of current running programs are located in the computers memory. Also know as Primary Memory its the location the CPU uses to retrieve en process data. There are 2 types of memory

* Cache
* Random Acces Memory

#### Cache

Cache memory is located within the CPU and is extremely fast compared to RAM as it runs on the same clock speed as the CPU. Onlye it is very limited in size. It stores frequently accessed data and instructions. Image a race as CPU and RAM as a delivery truck, the truck would slow down the race car, by storing in cache the CPU won't be slowed down.

{% tabs %}
{% tab title="Level 1 Cache" %}
Usually in kilobytes, the fastest memory available, located in each CPU core.
{% endtab %}

{% tab title="Level 2 Cache" %}
Usually in megabytes, extremely fast but slower than level 1, shared between all CPU cores.
{% endtab %}

{% tab title="Level 3 Cache" %}
Usually in megabytes, larger than level 2, faster than RAM but slower than level 1 and 2.
{% endtab %}
{% endtabs %}

#### RAM

Random access memory or RAM much larger than cache memory and ranging from gigabytes to terabytes. As is its further away from the CPU its also much slower and take more instructions. &#x20;

{% hint style="info" %}
Retrieving an instruction from the registers takes 1 clock cycle while retrieving it from RAM take around 200 cycles.&#x20;
{% endhint %}

Coming from 32-bit addresses the maximum memory address was limited to 4gb (2^32 bytes). In contrast, 64-bit addresses provide a much larger address space - up to 18.5 exabytes (2^64 bytes).

* 32 bits = 4,294,967,296 bytes
* 64 bits = 18,446,744,073,709,551,616 bytes

When running a program, all data and instructions are moved from the storage unit to the RAM so it can be accessed by the CPU. Accessing that from a storage unit would take a lot longer. Once a prorgram is closed the data is removed. RAM is divided in 4 segments:

<figure><img src="../../.gitbook/assets/image (132).png" alt=""><figcaption></figcaption></figure>

{% tabs %}
{% tab title="Stack" %}
Last-In-First-Out (LIFO) principle. Data in it can only be accessed in a specific order by push-ing and pop-ing data.
{% endtab %}

{% tab title="Heap" %}
Dynamic memory allocation, larger and more versatile in storing data.&#x20;
{% endtab %}

{% tab title="Data" %}
2 parts: Data and .bss and holds unassigned variables such as numbers, text, images, or code.
{% endtab %}

{% tab title="Text/Code" %}
Instructions that make up a program, loaded into this segment to be fetched and executed by the CPU.
{% endtab %}
{% endtabs %}

### <mark style="color:yellow;">IO/Storage</mark>

IO or input and output are our device like displays, keyboards, mouse or long-term storage units which are also called Secondary Memory. The processor access and controls these IO devices by using Bus interfaces, they are like highways to transfer data and addresses.&#x20;

Each bus has a capacity of bits or electrical charges it cary at the same time, ranging from 4-bits to 128-bits.&#x20;

<figure><img src="../../.gitbook/assets/image (133).png" alt=""><figcaption><p>Bus like highways on the mainboard</p></figcaption></figure>

