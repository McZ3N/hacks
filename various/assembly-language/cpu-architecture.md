---
description: >-
  The Central Processing Unit (CPU) is the main processing unit within a
  computer.
cover: ../../.gitbook/assets/francesco-vantini-ZavLsrP4CDI-unsplash.jpg
coverY: 0
---

# CPU Architecture

### <mark style="color:yellow;">CPU</mark>

The CPU contains both the Control Unit or CU which is responsible for controlling and moving data and the ALU or Arithmetic/Login Unit is in charge of performing arithmetics and logical calculations.&#x20;

{% tabs %}
{% tab title="RISC" %}
`RISC` architecture is based on processing more simple instructions, it will take more cycles, but each cycle is shorter and takes less power.

RISC = Reduced Instruction Set Computer
{% endtab %}

{% tab title="CISC" %}
`CISC` architecture is based on fewer, more complex instructions, and can finish the requested instructions in fewer cycles. Each instruction takes more time and power to be processed.

CISC = Complex Instruction Set Computer
{% endtab %}
{% endtabs %}

### <mark style="color:yellow;">Clock speed & clock cycle</mark>

{% hint style="info" %}
Processor clock speed measures the number of cycles a CPU can execute per second, measured in Hertz (Hz).
{% endhint %}

Every tick of the clock is a clock cycle that processes a basic instruction. Counting cycles per second is done in Hertz so when a CPU has a speed of 4.0 GHz it runs 4 billion cycles per second per core. Processor have multi-core design, allowing them to have multiple cycles at the same time.

### <mark style="color:yellow;">Instruction cycle</mark>

An Instruction Cycle is the cycle it takes the CPU to process a single machine instruction and consists of four layers.&#x20;

{% stepper %}
{% step %}
#### Fetch

Takes next instruction's address from IAR or Instruction Address Register.
{% endstep %}

{% step %}
#### Decode

Takes instruction from IAR and decodes from binary.
{% endstep %}

{% step %}
#### Execute

The operands, both source and destination, are fetched from memory or registers.
{% endstep %}

{% step %}
#### Store

Store values in destination operand or memory location
{% endstep %}
{% endstepper %}

Each instruction cycle takes multiple clock cycles to finish, depending on the CPU architecture and complexity of the instruction. Once 1 intstruction ends, it increments to the next and so on.

### <mark style="color:yellow;">Processors</mark>

Different processors understand different machine code instructions. This is due to their unique Instruction Set Architecture (ISA). The same machine code can mean different things on different processors. Even within the same ISA, there can be multiple syntax variations for the same instruction.



