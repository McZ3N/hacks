---
description: ISA specifies syntax of assembly language on architectures.
cover: ../../.gitbook/assets/shubham-dhage-AeF5ZV1LRRE-unsplash.jpg
coverY: 0
---

# Instruction Set Architectures

An **Instruction Set Architecture** (**ISA**) defines the language and rules for a computer's processor, covering both syntax and meaning. It is a fundamental part built in the core design of a processor, influencing how instructions are executed and their complexity.&#x20;

The main components that distinguish ISA's and assembly languages:

{% tabs %}
{% tab title="Instructions" %}
The instruction to be processed in the opcode operand\_list format.&#x20;
{% endtab %}

{% tab title="Registers" %}
Used to store operands, addresses, or instructions temporarily.
{% endtab %}

{% tab title="Memory addresses" %}
The address in which data or instructions are stored. May point to memory or registers.
{% endtab %}

{% tab title="Data Types" %}
The type of stored data.
{% endtab %}
{% endtabs %}

{% hint style="info" %}
<mark style="color:green;">Complex Instruction Set Computer or CISC</mark>

Used in `Intel` and `AMD` processors (most systems)

<mark style="color:green;">Reduced Instruction Set Computer or RISC</mark>

Used in `ARM` and `Apple` processors (smartphones/laptops)
{% endhint %}

### <mark style="color:yellow;">CISC</mark>

Complex Instruction Set Computer or CISC runs more complex instructions to be run at a time which reduces overall number of instructions. Adding 2 registers would be doen in a single Instruction cycle (Fetch-Decode-Execute-Store).&#x20;

### <mark style="color:yellow;">RISC</mark>

Reduced Instruction Set Computer or RISC runs by splittings instructions into minor instuctions as the CPU is designed to handle simple instructions. An  instruction "add r1, r2, r3" and to execute this, the processor must fetch the values from registers r2 and r3, add them, and then store the result in register r1. Each of these steps (fetch, decode, execute, store) requires a complete instruction cycle.

### <mark style="color:yellow;">Some key difference</mark>

|                        | CISC                        | RISC                                |
| ---------------------- | --------------------------- | ----------------------------------- |
| Complexity             | Favors complex instructions | Favors simple instructions          |
| Length of instructions | Multiples of 8-bits'        | Fixed length '32-bit/64-bit'        |
| Optimization           | Hardware optimized in CPU   | Software optimization (in Assembly) |
| Example                | Intel, ADM                  | ARM, Apple                          |
| Power consumption      | High                        | Very low                            |

