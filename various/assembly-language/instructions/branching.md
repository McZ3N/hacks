---
description: >-
  Branching instruction are general instructions that allow to jump any point in
  program.
---

# Branching

#### Unconditional branching

The JMP instruction is a basic control flow instruction in assembly that performs an unconditional jump to a specified location in code. If a program's execution is directed to another location it will continue processing from that point.&#x20;

{% hint style="info" %}
The basic `jmp` instruction is unconditional, which means that it will always jump to the specified location, regardless of the conditions.&#x20;

Unconditional branching will always jump is not suitable for loops as it will loop forever.
{% endhint %}

### <mark style="color:yellow;">Conditional branching</mark>

Conditional Branching is where the flow of execution is directed based on certain conditions, based on the Destination and Source operands. A conditional jump instruction has multiple varieties as `Jcc`, where `cc` represents the Condition Code.

<table><thead><tr><th width="147">Instruction</th><th width="145">Condition</th><th>Description</th></tr></thead><tbody><tr><td>jz</td><td>D = 0</td><td>Destination equal to 0</td></tr><tr><td>jnz</td><td>D != 0 </td><td>Destnation not equal to 0</td></tr><tr><td>js</td><td>D &#x3C; 0</td><td>Destination is negative</td></tr><tr><td>jsn</td><td>D >=</td><td>Destination is Not Negative (i.e. 0 or positive)</td></tr><tr><td>jg</td><td>D > S</td><td>Destination Greater than Source</td></tr><tr><td>jge</td><td>D >=</td><td>Destination Greater than or Equal Source</td></tr><tr><td>jl</td><td>D &#x3C; S</td><td>Destination Less than Source</td></tr><tr><td>jle</td><td>D &#x3C;= S</td><td>Destination Less than or Equal Source</td></tr></tbody></table>

The `cmovcc` (conditional move) instruction in assembly allows us to conditionally move data from one register to another only if a specific condition is met. This is different from regular `mov` instructions, which always move data without any condition.

```nasm
cmovz rax, rbx  ; Move rbx into rax if the condition (zero flag) is set, meaning the last result was zero.
```

#### RFLAG Register

When executing conditional instructions like `jmp`. The processor needs to know whether conditions are true or false.  It uses the RFLAGS register which consists of 64-bits and it holds flag bits instead of values. Each bit 'or set of bits' turns to `1` or `0` depending on the value of the last instruction.

```nasm
mov eax, 1      ; eax = 1
dec eax         ; eax = 0
; ZF is now 1 (on) because result was zero
; This is called the "Zero" (ZR) condition

mov eax, 2      ; eax = 2
dec eax         ; eax = 1
; ZF is now 0 (off) because result was not zero
; This is called the "Not Zero" (NZ) condition
```

There are more flag to work with: [https://www.geeksforgeeks.org/flag-register-8086-microprocessor/](https://www.geeksforgeeks.org/flag-register-8086-microprocessor/)

### <mark style="color:yellow;">CMP</mark>

If we want our program to stop at a certain value like 20 we can use `js loopExample` which will jump back took `loopExample` as long as the last instruction was a negative number. The compare instruction `cmp` compares 2 operands. by subtracting the second operand from first operand (i.e. `D1` - `S2`) and sets flag in RFLAGS.

#### So as example:

* When we have first number 1: `1 - 10 = -9`
  * Since -9 < 0, the jump condition is met
  * Program continues generating Fibonacci numbers
* When we reach 13: `13 - 10 = 3`
  * Since 3 > 0, the jump condition is not met
  * Program stops as we found first Fibonacci > 10



