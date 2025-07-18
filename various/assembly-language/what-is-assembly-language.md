---
description: Low-level language that writes instructions processors can understand
cover: ../../.gitbook/assets/binary-code.webp
coverY: 0
---

# What is Assembly Language

### <mark style="color:yellow;">Introduction</mark>

A processr can only process binary data or 1's and 0's. By using assembly we can write human-readable machine instructions. Assembly language is also referred to as machine code.&#x20;

{% hint style="info" %}
Assembly code '`add rax, 1`' is easier to remember than its equivalent machine shellcode '`4883C001`', and easier to remember than the equivalent binary machine code '`01001000 10000011 11000000 00000001`'.
{% endhint %}

Machine code is often represented as `Shellcode`. A hex representation of machine code bytes and shellcode can be converted back into its assembly language form and can also be loaded directly into memory as binary instructions for execution.

{% embed url="https://www.youtube.com/watch?ab_channel=Fireship&v=4gwYkEK0gOk" %}

### <mark style="color:yellow;">High-level vs. Low-level</mark>

Different processors understand different machine instructions. High level languages like C make it possible to write easy to understand code that can work on any proccessor. When high level code is compiled its translated into assembly instructions for the processor its being compiled for. Languages like Python, PHP, JS are usually not compiled but utilize pre-built libraries which are written and compiled in languages like C or C++.&#x20;

{% hint style="info" %}
Low-level languages are closer to machine code, providing more direct control over hardware but are more complex to program.
{% endhint %}

### <mark style="color:yellow;">Compiling process</mark>

In python we write a simple hello world program:

```python
print("Hello world")
```

The same program in C

```c
#include <stdio.h>

int main() {
    printf("Hello World!\n");
    return 0;
}
```

In assembly language this looks like&#x20;

```armasm
mov rax, 1
mov rdi, 1
mov rsi, message
mov rdx, 12
syscall

mov rax, 60
mov rdi, 0
syscall
```

And finally in binary

```
01001000 11000111 11000000 00000001
01001000 11000111 11000111 00000001
01001000 10001011 00110100 00100101
01001000 11000111 11000010 00001101 
00001111 00000101

01001000 11000111 11000000 00111100 
01001000 11000111 11000111 00000000 
00001111 00000101
```

