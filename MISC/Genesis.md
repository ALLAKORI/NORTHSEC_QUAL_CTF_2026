# 🧬 Genesis — NorthSec CTF (Misc)

## 🏷️ Challenge Overview

* **Category:** Misc / Bioinformatics / Crypto
* **Difficulty:** Hard
* **Concepts:** DNA steganography, codon usage encoding, ORF extraction, stream cipher

---

## 📖 Description

We are given a synthetic DNA sequence (`specimen_0.fasta`) along with lab notes describing a hidden message embedded in the genome.

The notes hint at:

* Codon redundancy used for encoding
* A subset of genes used as encryption key
* Reverse strand reading
* XOR encryption with a derived keystream

---

## 🧠 Analysis

### 🔬 1. Understanding the Encoding

From the lab notes:

> "Every amino acid has its favourite spelling… we choose a different one"

👉 Each amino acid can be encoded by multiple codons.
👉 This redundancy is used to encode bits.

---

### ⚖️ 2. Codon Selection Rule

> "We only touch redundancies that divide evenly"

👉 Only amino acids with:

* **2 codons → 1 bit**
* **4 codons → 2 bits**

Other codons are ignored.

---

### 🔤 3. Ordering

> "We use a different order: the one a dictionary uses"

👉 Codons must be **sorted alphabetically**, NOT by frequency.

---

### 🔄 4. Orientation

> "Orientation: reverse strand"

👉 The DNA must be processed using its **reverse complement**.

---

### 🧬 5. ORF Extraction

> "Six genes. Five boring, one loud."

👉 We must:

* Extract ORFs (ATG → STOP)
* Select **6 non-overlapping ORFs**
* The **longest = payload**
* The other **5 = key material**

---

### 🔐 6. Encryption Scheme

> "Concatenate. Hash. Stretch. XOR."

Interpretation:

1. Concatenate the 5 "quiet" ORFs
2. Generate keystream using:

   ```
   SHA256(key_material || counter)
   ```
3. XOR with payload

---

## ⚙️ Exploitation

### 🧪 Step 1 — Reverse Complement

```python
comp = str.maketrans("ATCG", "TAGC")
rev = seq.translate(comp)[::-1]
```

---

### 🧪 Step 2 — Extract ORFs

* Start codon: `ATG`
* Stop codons: `TAA`, `TAG`, `TGA`
* Keep ORFs with sufficient length

---

### 🧪 Step 3 — Select Relevant ORFs

* Sort by length
* Keep **6 non-overlapping ORFs**

---

### 🧪 Step 4 — Convert Codons → Bits

Example:

| Codons | Bits |
| ------ | ---- |
| TTC    | 0    |
| TTT    | 1    |

| Codons | Bits |
| ------ | ---- |
| GCA    | 00   |
| GCC    | 01   |
| GCG    | 10   |
| GCT    | 11   |

---

### 🧪 Step 5 — Extract Payload

* Skip start + stop codons
* Convert codons → bitstream → bytes

---

### 🧪 Step 6 — Generate Keystream

```python
def keystream(material, n):
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(material + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:n]
```

---

### 🧪 Step 7 — Decrypt

```python
plaintext = bytes(a ^ b for a, b in zip(payload_bytes, keystream))
```

---

## 🧾 Full Exploit Script

```python
# (script complet utilisé pour résoudre le challenge)
# [identique à celui utilisé dans la résolution]
```

---

## 🏁 Result

```text
NSC{th3_l1v1ng_d34d_dr0p_h4s_4_qu13t_4cc3nt}
```

---

## 💡 Key Takeaways

* DNA can be used as a steganographic medium via codon redundancy
* ORF structure can hide logical separation of data (payload vs key)
* Reverse strand processing is a common trick
* Custom stream ciphers often rely on hash + counter construction

---

## 🔥 Conclusion

This challenge combines:

* Bioinformatics
* Steganography
* Cryptography

A great example of multidisciplinary CTF design where understanding the **domain context (biology)** is as important as exploitation skills.

---
