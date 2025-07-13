---
description: Moving data and loading data into registers.
---

# Basic Instructions

One of the most important instruction in assembly language is data movement. Its used to move data between addresses, moving data between registers and memory addresses, and loading immediate data into registers or memory addresses. The main Data Movement instructions are:

| Instruction | Description                 | Example  |
| ----------- | --------------------------- | -------- |
| mov         | Move or load data           | mov rax  |
| lea         | Load address point to value | lea rax  |
| xchg        | Swap data                   | xchg rax |

{% hint style="info" %}
We can say `mov` is much more like a `copy` function, rather than an actual move.
{% endhint %}

### <mark style="color:yellow;">Moving data</mark>

If we want to load values 0 and 1 we can use the `mov` instruction and `mov 0` to `rax` and `move 1` to `rbx`.

```nasm
global  _start

section .text
_start:
    mov rax, 0
    mov rbx, 1
```

### <mark style="color:yellow;">Loading data</mark>

Using the `mov` instruction we can also load immediate data. We can load the value of 1 into the rax register but since the size of the loaded data depends on the size of the register its not efficiënt to `mov rax 1` into a 64-bit register `rax`. A better solution is to use `mov al, 1`  which will place 1 into the 8--bit or 1 byte register.&#x20;

```nasm
global  _start

section .text
_start:
    mov al, 0
    mov bl, 1
```

{% hint style="info" %}
Using the `xchg` instruction will swap the data between the two registers.
{% endhint %}

### <mark style="color:yellow;">Address pointers</mark>

When an register or address points contains another address which points to the final value we call these pointer registers, like `rsp`, `rbp` and `rip`.

```nasm
$rsp   : 0x00007fffffffe490  →  0x0000000000000001
$rip   : 0x0000000000401000  →  <_start+0> mov eax, 0x0
```

RSP register points to the top of the stack, 0x0000000000000001. RIP register points to the next instruction to be executed

### <mark style="color:yellow;">Moving Pointer Values</mark>

The register `rsp` (stack pointer) holds a memory address which points to a value stored in memory. It holds an address instead of actual data. &#x20;

```nasm
$rsp   : 0x00007fffffffe490  →  0x0000000000000001
$rip   : 0x0000000000401000  →  <_start+0> mov eax, 0x0
```

In this case `rsp` is `0x00007fffffffe490` where value `0x1` is stored. To move this value we will have to use \[ ] w x86\_64 assembly means "load value at address". If we want to move the value `rsp` is pointing to we use square brackets like, mov rax, \[rsp] which moves to final value.

{% hint style="info" %}
`mov rax, [rsp+10]` to move the value stored 10 address away from `rsp`.
{% endhint %}

Recap

* `mov rax, rsp`: Moves the address in `rsp` to `rax`.
* `mov rax, [rsp]`: Moves the value at the address in `rsp` to `rax`

```nasm
global  _start

section .text
_start:
    mov rax, rsp ; gets the address
    mov rax, [rsp] ; get the value at address
```

```nasm
# First instruction, copied rsp into rax.
$rax   : 0x00007fffffffe490  →  0x0000000000000001
$rsp   : 0x00007fffffffe490  →  0x000000000000000

# Second instruction, copied value intro rax
─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 →   0x401003 <_start+3>       mov    rax, QWORD PTR [rsp]
───────────────────────────────────────────────────────────────────────────────────── registers
$rax   : 0x1               
$rsp   : 0x00007fffffffe490  →  0x0000000000000001
```

We may need to set data size, like byte or qword but usually nasm will do this.&#x20;

### <mark style="color:yellow;">Loading value pointers</mark>

Using `lea` instruction we can load a pointer address to a value. Lea or Load Effective Address is the opposite of moving pointers. If we need to load the address of a value instead of loading actual data. It will only load the address itself.

```nasm
global  _start

section .text
_start:
    lea rax, [rsp+10]
    mov rax, [rsp+10]
```

```nasm
# First instruction
$rax   : 0x00007fffffffe49a  →  0x000000007fffffff
$rsp   : 0x00007fffffffe490  →  0x0000000000000001

# Second instruction
$rax   : 0x7fffffff        
$rsp   : 0x00007fffffffe490  →  0x0000000000000001
```

* `lea rax, [rsp+10]` loaded the address that is 10 addresses away from `rsp` . `rsp` is `0x00007fffffffe490`, so `rsp + 10` is `0x00007fffffffe49a`.
* `mov rax, [rsp+10]` moved the value stored at `0x00007fffffffe49a` which is `0x7fffffff` into rax.&#x20;

{% hint style="info" %}
**`lea`** is used to calculate an address and store it in a register **`mov`** with brackets (`[]`) retrieves the actual data at the given address.
{% endhint %}

### <mark style="color:yellow;">Example</mark>

What is the hex value of `rax` at the end of the program after adding `mov rax, rsp`.

```nasm
global _start

section .text
_start:
    mov rax, 1024    ; rax = 1024 (0x400)
    mov rbx, 2048    ; rbx = 2048 (0x800)
    xchg rax, rbx    ; swaps values rax and rbx
    push rbx         ; rsp now points to where 1024 is stored
    mov rax, rsp     ; rax gets the ADDRESS (0x7fffffffdda8) of where 1024 is stored
```

rsp contains an ADDRESS (0x7fffffffdda8) and at that address, the VALUE stored is 1024 (0x400). To check the values of end of program:

<details>

<summary>gdb output</summary>

```nasm
$rax   : 0x00007fffffffdda8  →  0x0000000000000400
$rbx   : 0x400             
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffdda8  →  0x0000000000000400
$rbp   : 0x0               
$rsi   : 0x0               
$rdi   : 0x0               
$rip   : 0x0000000000401010  →   add BYTE PTR [rax], al
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x0               
$r11   : 0x0               
$r12   : 0x0               
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdda8│+0x0000: 0x0000000000000400	 ← $rax, $rsp
0x00007fffffffddb0│+0x0008: 0x0000000000000001
0x00007fffffffddb8│+0x0010: 0x00007fffffffe147  →  "/home/kali/Downloads/mov"
0x00007fffffffddc0│+0x0018: 0x0000000000000000
0x00007fffffffddc8│+0x0020: 0x00007fffffffe160  →  "SHELL=/bin/zsh"
0x00007fffffffddd0│+0x0028: 0x00007fffffffe16f  →  "SESSION_MANAGER=local/kali:@/tmp/.ICE-unix/1839,un[...]"
0x00007fffffffddd8│+0x0030: 0x00007fffffffe1bd  →  "QT_ACCESSIBILITY=1"
0x00007fffffffdde0│+0x0038: 0x00007fffffffe1d0  →  "COLORTERM=truecolor"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40100a <_start+000a>    xchg   rbx, rax
     0x40100c <_start+000c>    push   rbx
     0x40100d <_start+000d>    mov    rax, rsp
 →   0x401010                  add    BYTE PTR [rax], al
     0x401012                  add    BYTE PTR [rax], al
     0x401014                  add    BYTE PTR [rax], al
     0x401016                  add    BYTE PTR [rax], al
     0x401018                  add    BYTE PTR [rax], al
     0x40101a                  add    BYTE PTR [rax], al
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "mov", stopped 0x401010 in ?? (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401010 → add BYTE PTR [rax], al
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  print $rax
$1 = 0x7fffffffdda8

```

</details>

```bash
gef➤  b _start
gef➤  r

# Stop after line mov rax, rsp
$rax   : 0x00007fffffffdda8  →  0x0000000000000400
$rbx   : 0x400             
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffdda8  →  0x0000000000000400

# Get address and value
gef➤  x/x $rax
0x7fffffffdda8:	0x00000400
```
