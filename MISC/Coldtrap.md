# 🧊 ColdTap — Misc / Crypto Writeup

**Category:** Misc / Hardware / Crypto
**Difficulty:** Hard
**Event:** NorthSec CTF

---

## 📜 Description

> The sponsor badge uses a “secure” NFC wallet.
> The key never leaves the card… right? 👀

We are given:

* `badge_fw.bin` → firmware of the NFC badge
* `hallway_*.pcapng` → captured interactions with the badge
* `SponsorVault.sol` → smart contract
* `instance.json` → contains encrypted flag

---

## 🎯 Objective

Recover the private key used by the badge and decrypt the offline flag blob:

```json
"flagCiphertext": "0x93517119450be8fbcd18e2a009656a9a0b49cea8b155a78bba05477b0645213bdf8aac593fdd0296e7fc66d4"
```

---

## 🔍 Step 1 — Firmware Analysis

```bash
file badge_fw.bin
strings -a badge_fw.bin
```

Relevant findings:

```text
eip712 domain: SponsorVault|1
eip712 type: CheckIn(address attendee,uint256 boothId,bytes32 nonce)
flagwrap: keccak-xor-v1|coldtap/flag-mask
Sponsor booth acknowledgement #7118
```

---

## 📡 Step 2 — PCAP Analysis

The captures use a custom protocol (`USER 0`), so we extract raw bytes:

```python
from scapy.all import PcapNgReader, raw

for pkt in PcapNgReader("hallway_02.pcapng"):
    print(raw(pkt).hex())
```

### APDU Structure

```
00 A4 → SELECT applet (COLDTAP)
80 20 → select profile
80 10 → metadata
80 30 → SIGN
```

---

## ✍️ Step 3 — Extract Signatures

### 📌 Signature 1 (hallway_02)

Message:

```
"Sponsor booth acknowledgement #7118"
```

Signature:

```
r = fbba367c94410e3829e7dee05d88c784a38e41e9dcd37cfdbdf9d6bf10264e40
s1 = 264493501fbe04b46af480952ae0ddef5a7c1605d1365185f4ca845a228b1f66
```

---

### 📌 Signature 2 (hallway_05)

EIP-712:

```
CheckIn(attendee, boothId=7118, nonce)
```

Signature:

```
r = fbba367c94410e3829e7dee05d88c784a38e41e9dcd37cfdbdf9d6bf10264e40
s2 = 4260df7d8ea67fa97985a400ec922b09d824a088c397b8a485807ddebb75e356
```

---

## 💣 Step 4 — Vulnerability

```
r1 == r2
```

Nonce reuse in ECDSA → same `k`

---

## 🧠 Step 5 — Recover Private Key

```
k = (z1 - z2) * inverse(s1 - s2) mod n
d = (s1*k - z1) * inverse(r) mod n
```

```
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

Hashes:

```
z1 = keccak256("\x19Ethereum Signed Message:\n34" + msg)
z2 = keccak256("\x19\x01" + domainSeparator + structHash)
```

Recovered private key:

```
0xfaee39661a1b1ff81be264a13e44ee9a28263665af0289c69407cefd4d18926f
```

---

## 🔐 Step 6 — Decrypt Flag

```
flagwrap: keccak-xor-v1|coldtap/flag-mask
```

```
mask = keccak(label + privkey + counter)
plaintext = ciphertext XOR mask
```

---

## 🧾 Solve Script

```python
from hashlib import sha3_256

def keccak(x):
    return sha3_256(x).digest()

ct = bytes.fromhex("93517119450be8fbcd18e2a009656a9a0b49cea8b155a78bba05477b0645213bdf8aac593fdd0296e7fc66d4")
priv = bytes.fromhex("faee39661a1b1ff81be264a13e44ee9a28263665af0289c69407cefd4d18926f")

label = b"coldtap/flag-mask"
seed = label + priv

mask = b""
ctr = 0
while len(mask) < len(ct):
    mask += keccak(seed + ctr.to_bytes(4, "big"))
    ctr += 1

pt = bytes(a ^ b for a, b in zip(ct, mask))
print(pt.decode())
```

---

## 🏁 Flag

```
NSC{c0ldt4p_n0nc3_r3u53_cr0553d_th3_41r_g4p}
```

---

## 💀 TL;DR

```
Same r → same nonce → recover private key → derive mask → XOR → flag
```
