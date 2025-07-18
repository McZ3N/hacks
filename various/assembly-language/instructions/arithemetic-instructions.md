---
description: Perform mathematical computations on data.
---

# Arithemetic instructions

With Arithemetic Instructions we can perform mathematical computations on data in registers and memory addresses. These are usually processed by the ALU in the CPU. There are 2 types of instructions:

* Unary: Take online 1 operand.
* Binary: Takes 2 operands.

### <mark style="color:yellow;">Unary instructions</mark>

The main Unary instructions when using `rax` start as 1.:

<table><thead><tr><th width="153">Instruction</th><th width="179">Description</th><th>Example</th></tr></thead><tbody><tr><td>inc</td><td>Increment by 1</td><td><code>inc rax</code> -> <code>rax++</code> or <code>rax += 1</code> -> <code>rax = 2</code></td></tr><tr><td>dec</td><td>Decrement by 1</td><td><code>dec rax</code> -> <code>rax--</code> or <code>rax -= 1</code> -> <code>rax = 0</code></td></tr></tbody></table>

Lets make a small program that increments by 1

```nasm
global  _start
section .text
_start:
    mov al, 0
    mov bl, 0
    inc bl        
```

```bash
gef➤ b _start
gef➤ r

# returns 
─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x40100a <_start+10>      inc    bl
───────────────────────────────────────────────────────────────────────────────────── registers ────
$rbx   : 0x1           
```

### <mark style="color:yellow;">Binary instructions</mark>

We'll assume that both `rax` and `rbx` start as `1` for each instruction.

<table><thead><tr><th width="149">Intstruction</th><th>Description</th><th>Example</th></tr></thead><tbody><tr><td>add</td><td>Add both operands</td><td><code>add rax, rbx</code> -> <code>rax = 1 + 1</code> </td></tr><tr><td>sub</td><td>Subtract Source from Destination </td><td><code>sub rax, rbx</code> -> <code>rax = 1 - 1</code> </td></tr><tr><td>imul</td><td>Multiply both operands</td><td><code>sub rax, rbx</code> -> <code>rax = 1 - 1</code> </td></tr></tbody></table>

Lets make a small program with `add`.

```nasm
global  _start

section .text
_start:
   mov al, 0
   mov bl, 0
   inc bl
   add rax, rbx
```

We can see after processing the instruction rax is now equal to 0x1. Sub and imul work the same way.

```bash
gef➤  b _start
Breakpoint 1 at 0x401000
gef➤  r

─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401004 <_start+4>       inc    bl
 →   0x401006 <_start+6>       add    rax, rbx
───────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1
$rbx   : 0x1
```

### <mark style="color:yellow;">Bitwise instructions</mark>

Bitwise instructions are instructions that work bit level, assuming rax = 1 and rbx = 2 for each instruction.

<table><thead><tr><th width="138">Instruction</th><th>Description</th><th>Example</th></tr></thead><tbody><tr><td>not</td><td>Bitwise NOT (invert all bits, 0->1 and 1->0)</td><td><code>not rax</code> -> <code>NOT 00000001</code> -> <code>11111110</code></td></tr><tr><td>and</td><td>Bitwise AND (if both bits are 1 -> 1, if bits are different -> 0)</td><td><code>and rax, rbx</code> -> <code>00000001 AND 00000010</code> -> <code>00000000</code></td></tr><tr><td>or</td><td>Bitwise OR (if either bit is 1 -> 1, if both are 0 -> 0)</td><td><code>or rax, rbx</code> -> <code>00000001 OR 00000010</code> -> <code>00000011</code></td></tr><tr><td>xor</td><td>Bitwise XOR (if bits are the same -> 0, if bits are different -> 1)</td><td><code>xor rax, rbx</code> -> <code>00000001 XOR 00000010</code> -> <code>00000011</code></td></tr></tbody></table>

```nasm
; not instruction
mov rax, 1       ; rax = 1 (0001 in binary)
not rax          ; inverts all bits: (1110 in binary)

; and instruction
mov rax, 5       ; 0101
mov rbx, 3       ; 0011
and rax, rbx     ; 0001 (1 because only rightmost bit is 1 in both)

; or instruction
mov rax, 5       ; 0101
mov rbx, 3       ; 0011
or rax, rbx      ; 0111 (if either bit is 1, result is 1)
```

#### XOR Instruction

The XOR (eXclusive OR) instruction is a bitwise operation that compares two bits. It returns 1 if the two bits are different, and 0 if they are the same. Since every bit in `rax` is similar and is being compared to itself, the result is a register filled with zeros.

```nasm
global  _start

section .text
_start:
    xor rax, rax
    xor rbx, rbx
    inc rbx
    add rax, rbx
```

```nasm
$ ./assembler.sh fib.s -g
gef➤  b _start
Breakpoint 1 at 0x401000
gef➤  r
─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x401001 <_start+1>       xor    eax, eax
     0x401003 <_start+3>       xor    ebx, ebx
───────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0
$rbx   : 0x0

─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x40100c                  add    BYTE PTR [rax], al
───────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1
$rbx   : 0x1
```

{% hint style="info" %}
XOR is more efficient and ensures the entire registers are cleared before doing any operations, uses fewer CPU cycles.
{% endhint %}



