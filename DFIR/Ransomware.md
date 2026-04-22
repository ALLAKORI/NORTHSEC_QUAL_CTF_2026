
# 🧠 Ransomware — Forensic Writeup

![Category](https://img.shields.io/badge/category-forensics-blue)
![Difficulty](https://img.shields.io/badge/difficulty-medium-yellow)
![Event](https://img.shields.io/badge/event-NorthSec%20CTF-red)

---

## 📜 Description

> A forensic image has been provided after a ransomware infection.  
> Can you recover the flag?

**Flag format:** `NSC{...}`

---

## 📂 Initial Analysis

We are given a file:

```bash
file chall.ad1
````

Output:

```
chall.ad1: data
```

👉 The `.ad1` format corresponds to an **AccessData Logical Image (FTK)**.

---

## 🔧 Mounting the AD1 Image

Standard tools (`ewfmount`, `affuse`) do not support `.ad1`, so we use:

```bash
git clone https://github.com/al3ks1s/AD1-tools.git
cd AD1-tools
./autogen.sh
./configure
make
sudo make install
```

Mount the image:

```bash
mkdir /tmp/ad1mnt
ad1mount -i ../chall.ad1 -m /tmp/ad1mnt
```

---

## 🔍 Exploring the File System

We list files:

```bash
find /tmp/ad1mnt -maxdepth 5 | head
```

We notice many `.locked` files → typical ransomware behavior.

Example:

```bash
/tmp/ad1mnt/Users/oliver/Desktop/flag.txt.locked
```

---

## 🚨 Suspicious Script Discovery

We search for scripts:

```bash
find /tmp/ad1mnt -iname "*.ps1"
```

Found:

```bash
/tmp/ad1mnt/Windows/WinSxS/Temp/PendingDeletes/launcher.ps1
```

---

## 🧠 Analyzing `launcher.ps1`

```bash
sed -n '1,200p' launcher.ps1
```

The script is **heavily obfuscated** using:

* string concatenation
* reverse
* ROT13
* Base64 encoding

---

## 🔓 Deobfuscation

We reconstruct the hidden string:

```bash
echo "renjzbfanE/7331qvXbgclep/zbp.ohugvt//:fcggu" | rev | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

Output:

```
https://github.com/cryptoKid1337/Ransomware
```

---

## 📦 Malware Behavior

From the script:

* Clones a GitHub repository
* Executes a Python script (`sss.py`)
* Deletes traces

---

## 🧩 Recovering the Encryption Logic

From the repository:

👉 The ransomware uses **XOR encryption with a repeating key**:

```python
key = b"SuperSecretKey123!"
```

---

## 🔓 Decrypting Files

We decrypt the flag file:

```bash
python3 - <<'PY'
key = b"SuperSecretKey123!"
src = "/tmp/ad1mnt/Users/oliver/Desktop/flag.txt.locked"

with open(src, "rb") as f:
    data = f.read()

dec = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
print(dec.decode())
PY
```

Output:

```
EJT{i3g0_b3pJ_lec0tb_ky3_i4e50d}
```

---

## 🤔 Something is Wrong...

❌ Not valid flag format (`NSC{}` expected)

---

## 🧠 Final Step — Caesar Cipher

We apply a Caesar shift brute-force:

```bash
python3 - <<'PY'
s='EJT{i3g0_b3pJ_lec0tb_ky3_i4e50d}'
for k in range(26):
    out=[]
    for c in s:
        if 'a' <= c <= 'z':
            out.append(chr((ord(c)-97+k)%26+97))
        elif 'A' <= c <= 'Z':
            out.append(chr((ord(c)-65+k)%26+65))
        else:
            out.append(c)
    print(k, ''.join(out))
PY
```

At shift **9**, we get:

```
NSC{r3p0_k3yS_unl0ck_th3_r4n50m}
```

---

## 🏁 Final Flag

```
NSC{r3p0_k3yS_unl0ck_th3_r4n50m}
```

---

## 💡 Key Takeaways

* `.ad1` requires specialized forensic tools
* PowerShell obfuscation techniques:

  * string concatenation
  * reverse
  * ROT13
  * Base64
* Ransomware used weak crypto:

  * XOR with static key
* Multi-layer challenge:

  * Forensics → Reverse → Crypto

---

## 🧠 Conclusion

This challenge combines:

* Disk forensics
* Malware analysis
* Cryptography

👉 A realistic ransomware investigation scenario.

---

```
```
