---
description: Learning assembly instructions, writing code, assembling it, and debugging it.
---

# Assemble & Debug

### <mark style="color:yellow;">Assembly file structure</mark>

An Assembly file is structured into **sections** and **directives** that organize code and data. The `.data` section typically holds variables and constants, while the `.text` section contains the executable code.

Below a basic file structure of an assembly file. This file will print "Hello world!" to the screen.&#x20;

```armasm
         global  _start

         section .data
message: db      "Hello world!"

         section .text
_start:
         mov     rax, 1
         mov     rdi, 1
         mov     rsi, message
         mov     rdx, 18
         syscall

         mov     rax, 60
         mov     rdi, 0
         syscall
```

Instructions are commands that tell the CPU what operation to perform such as `mov`, `add`, `sub`, `mul`, or `syscall`. The operands are the targets of the instructions, typically registers and memory adresses.&#x20;

<figure><img src="../../.gitbook/assets/ass_tab2.png" alt=""><figcaption><p><code>.data</code> and <code>.text</code> sections refer to the <code>data</code> and <code>text</code> memory segment</p></figcaption></figure>

* global\_start: will direct the code to start executing at the `_start` label defined below.
* section .date: data section, which should contain all of the variables.
* section.text: will containt all text/code to be executed.

### <mark style="color:yellow;">Variables</mark>

The .data section hold variables which we can define, once running our programm all our variables will be loaded into memory in the data segment. We can define variables by using `db` for list of bytes, `dw` for word and `dd` for digits.

### <mark style="color:yellow;">Code</mark>

The .text section which is most important holds our code and asseymbly instructions which are loaded in the text memory segment. Once all instructions are loaded into the text segment the process will execute them one after another.&#x20;

## Assembling

As shown above how an assymbly file is build we can assemble a file using the nasm tool. The entire file structure is based on the nasm file structure. After assembling we can link it using `ld` to elf.

<details>

<summary>helloworld.s</summary>

```
global _start

section .data
    message db "Hello World!"
    length equ $-message

section .text
_start:
    mov rax, 1
    mov rdi, 1
    mov rsi, message
    mov rdx, length
    syscall

    mov rax, 60
    mov rdi, 0
    syscall
```

To assemble to helloworld.s file we use nasm with -f elf64 to assemble 64 bit.

```
nasm -f elf64 helloworld.s
```

From this we got a helloworld.o object file but its not executable yet, to make it executable we have to link it with OS libraries in this case Linux as an .elf file.

```
ld -o helloworld helloworld.o
```

This created our .elf file which we can run

```
$ ./helloworld                                                                                                  
Hello World! 
```

</details>

## Disassembling

To disassemble a file we can use objdump which dumps machine code from a file and interprets the assembly instruction of each hex code. Using `-M inte`l its will write in intel syntax, `-d` is for dissasemble.

```bash
$ objdump -M intel -d helloworld
helloworld:     file format elf64-x86-64

Disassembly of section .text:

0000000000401000 <_start>:
  401000:	b8 01 00 00 00       	mov    eax,0x1
  401005:	bf 01 00 00 00       	mov    edi,0x1
  40100a:	48 be 00 20 40 00 00 	movabs rsi,0x402000
  401011:	00 00 00 
  401014:	ba 0c 00 00 00       	mov    edx,0xc
  401019:	0f 05                	syscall
  40101b:	b8 3c 00 00 00       	mov    eax,0x3c
  401020:	bf 00 00 00 00       	mov    edi,0x0
  401025:	0f 05                	syscall
```

### <mark style="color:yellow;">Searching for strings</mark>

We can use `--no-show-raw-insn --no-addresses` to only show assembly code. If we want to look for strings we can use `objdump -sj .data helloworld`

```bash
$ objdump -sj .data helloworld
helloworld:     file format elf64-x86-64

Contents of section .data:
 402000 48656c6c 6f20576f 726c6421           Hello World!  
```

## GNU Debugger

Debuggin is finding, fixing and removing bugs from code. We perform debugging by setting breakpoints and watching how the program acts to find out what is causing the bug and how to fix it.

To start debugging we use `info functions`

```bash
$ gdb -q ./helloworld                                                        
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _start
```

To get variables: `info variables` .  This return the message variable.

```bash
gef➤  info variables
All defined variables:

Non-debugging symbols:
0x0000000000402000  message
0x000000000040200c  __bss_start
0x000000000040200c  _edata
0x0000000000402010  _end
```

### <mark style="color:yellow;">Disassemble with GDB</mark>

To disassemble we can use disas along with the function name: `disas _start`

```bash
gef➤  disas _start
Dump of assembler code for function _start:
   0x0000000000401000 <+0>:	mov    eax,0x1
   0x0000000000401005 <+5>:	mov    edi,0x1
   0x000000000040100a <+10>:	movabs rsi,0x402000
   0x0000000000401014 <+20>:	mov    edx,0xc
   0x0000000000401019 <+25>:	syscall
   0x000000000040101b <+27>:	mov    eax,0x3c
   0x0000000000401020 <+32>:	mov    edi,0x0
   0x0000000000401025 <+37>:	syscall
End of assembler dump.
```

### <mark style="color:yellow;">Debuggin with GDB</mark>

Debuggin with GDB is done with break, examine, step and modify. The first step of debugging is setting breakpoint which will stop the code executing at those breakpoints. This way we can see how each step changes the program and value.

We can set a breakpoint with `b _start` and then user `r` to run. If we want to set a breakpoint at a certain address at \_start+5, we can use `b *_start+10`.

<details>

<summary>Setting breakpoint at b _start</summary>

```bash
gef➤  b _start
Breakpoint 1 at 0x401000
gef➤  r
Starting program: /home/kali/Scripts/helloworld 

Breakpoint 1, 0x0000000000401000 in _start ()

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffdda0  →  0x0000000000000001
$rbp   : 0x0               
$rsi   : 0x0               
$rdi   : 0x0               
$rip   : 0x0000000000401000  →  <_start+0000> mov eax, 0x1
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
0x00007fffffffdda0│+0x0000: 0x0000000000000001	 ← $rsp
0x00007fffffffdda8│+0x0008: 0x00007fffffffe138  →  "/home/kali/Scripts/helloworld"
0x00007fffffffddb0│+0x0010: 0x0000000000000000
0x00007fffffffddb8│+0x0018: 0x00007fffffffe156  →  "NMAP_PRIVILEGED="
0x00007fffffffddc0│+0x0020: 0x00007fffffffe167  →  "SSH_AUTH_SOCK=/tmp/ssh-ES0kfvGeRC3S/agent.1928"
0x00007fffffffddc8│+0x0028: 0x00007fffffffe196  →  "SESSION_MANAGER=local/kali:@/tmp/.ICE-unix/1791,un[...]"
0x00007fffffffddd0│+0x0030: 0x00007fffffffe1e4  →  "LANG=en_US.UTF-8"
0x00007fffffffddd8│+0x0038: 0x00007fffffffe1f5  →  "SSH_AGENT_PID=1929"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400ffa                  add    BYTE PTR [rax], al
     0x400ffc                  add    BYTE PTR [rax], al
     0x400ffe                  add    BYTE PTR [rax], al
●→   0x401000 <_start+0000>    mov    eax, 0x1
     0x401005 <_start+0005>    mov    edi, 0x1
     0x40100a <_start+000a>    movabs rsi, 0x402000
     0x401014 <_start+0014>    mov    edx, 0xc
     0x401019 <_start+0019>    syscall 
     0x40101b <_start+001b>    mov    eax, 0x3c
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "helloworld", stopped 0x401000 in _start (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401000 → _start()
```

</details>

#### Examine instructions

To manually examin addresses or registers we can use the `x` in a format like `x/FMT ADDRESS`. The FMT is examine format and has 3 parts

1. Count  -  Number of times to repeat the examine  -  LIke 2, 3 or 10
2. Format  -  Format result to be represented in  -  x(hex), s(string), i (instruction)
3. Size  -  Size of memory we examine  -  b(byte), h(halfword), w(word), g(giant, 8 bytes)

In the output of b -start above we can see $rip would be the address of our next instruction we can use `x/4ig $rip`. So this will show 4 instructions in 8 bytes.

#### Examine strings

Its possible to examine variables stored at specific memory adresses. In our helloworld program we have a message variable "hello word!" stored at .data on address 0x402000. So lets examine this address:

```bash
gef➤  x/s 0x402000
0x402000:	"Hello World!"
```

#### Addresses

Most common format of examining is hex. Lets try this with `x/wx 0x401000`.&#x20;

```bash
# "Hello world!" in hex
gef➤  x/x 0x402000
0x402000:	0x6c6c6548
```

#### Step

In debugging its possible to step through the program one instruction or line of code at a time. With `stepi` or `si` it wel step through the assembly one by one.

```bash
# Set breakpoint at _start
gef➤  b _start
# Run 
gef➤  r
# Step with si
gef➤  si
```

{% hint style="info" %}
`next` or `n` command, which will also continue until the next line, but will skip any functions and `nexti` or `ni`, which is similar to `si`, but skips functions calls.
{% endhint %}

#### Modify

Modifying values using GDB can be done by using thet `set` command. As our string "Hello World" is at  0x40200 we set a breakpoint at 0x401019.

```bash
gef➤  break *0x401019
gef➤  r
gef➤  patch string 0x402000 "Changed!\\x0a"
gef➤  c
Continuing.
Changed!
```





