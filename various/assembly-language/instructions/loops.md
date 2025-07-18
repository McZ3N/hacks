---
description: >-
  Program Control Instructions like loops gives us control of the flow of a
  program.
---

# Loops

Assembly like most languages is line-based, it will look to the following line for the next instruction. Contro instructions gives us the ability to change the flow of the program. Other types of control instructions are Branching and Function Calls.&#x20;

### <mark style="color:yellow;">Loop Structure</mark>

A loop is set of instructions that repeat for `rxc` times.&#x20;

```nasm
exampleLoop:
    instruction 1
    instruction 2
    instruction 3
    loop exampleLoop
```

Once the code reaches exampleLoop it will start executing the instructions under it. We can set the number of iterations in the `rcx` register. If the loop reaches the loop instruction it will decrease by 1. Before entering a loop, `mov` the number of loop iterations to the `rcx` register.&#x20;

<table><thead><tr><th width="189">Instruction</th><th>Description</th><th>Example</th></tr></thead><tbody><tr><td>mov rcx, x</td><td>Sets loop rxc counter to x</td><td>mov rcx, 3</td></tr><tr><td>loop</td><td>Back to start of loop until 0</td><td>loop exampleLoop</td></tr></tbody></table>

Example fibonacci

```nasm
global  _start

section .text
_start:
    xor rax, rax    ; initialize rax to 0
    xor rbx, rbx    ; initialize rbx to 0
    inc rbx         ; increment rbx to 1
    mov rcx, 10     ; 10 iterations
loopFib:
    add rax, rbx    ; get the next number
    xchg rax, rbx   ; swap values
    loop loopFib
```

Fibonacci is the sum of the two preceding ones so: 0, 1, 1, 2, 3, 5, 8.

* We store current num in `rax` and next num in `rbx`.
* `xor` cleans register
* `inc rbx` will run once to set rbx to 1
* sum of rax and rbx
* Swap `rax` with `rbx`.
* Loop&#x20;

Why swap `rax` with `rbx`? Swapping ensures that `rbx` always holds the previous Fibonacci number and `rax` holds the current one.

<table><thead><tr><th width="172">Step </th><th width="116">rax value</th><th width="106">rbx value</th><th>Description</th></tr></thead><tbody><tr><td>Initialization</td><td>0</td><td>0</td><td><code>xor rax, rax</code> and <code>xor rbx, rbx</code></td></tr><tr><td>Increment</td><td>0</td><td>1</td><td>inc rbx (once)</td></tr><tr><td>Loop start</td><td>0</td><td>1</td><td>mov rcx, 10</td></tr><tr><td>1st iteration</td><td>1</td><td>1</td><td><code>add rax, rbx</code> (0 + 1 = 1)</td></tr><tr><td></td><td>1</td><td>1</td><td><code>xchg rax, rbx</code> (swap)</td></tr><tr><td>2nd iteration</td><td>2</td><td>1</td><td><code>add rax, rbx</code> (1 + 1 = 2)</td></tr><tr><td></td><td>1</td><td>2</td><td><code>xchg rax, rbx</code> (swap)</td></tr><tr><td>3rd iteration</td><td>3</td><td>2</td><td><code>add rax, rbx</code> (1 + 2 = 3)</td></tr><tr><td></td><td>2</td><td>3</td><td><code>xchg rax, rbx</code> (swap)</td></tr></tbody></table>

