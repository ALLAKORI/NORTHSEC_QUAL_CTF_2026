
## Writeup: Sanity Check (259) – NorthSec 2026

### 1. Challenge Overview
* **Name**: Sanity Check
* **Category**: Warmup / Misc
* **Author**: Fairalien
* **Objective**: Locate the hidden flag to validate the connection to the NorthSec CTF platform.

### 2. Reconnaissance & Analysis
Upon examining the CTF landing page (**Andalusian Cipher**), a technical dashboard displayed a specific card with the following metadata:

* **Transmission Channel**: `CTF.NORTHSEC.MA`
* **Protocol Metadata**: `_RISALA · IN · TXT`
* **Current Status**: `RECORD UNRESOLVED`

The keywords **"IN"** and **"TXT"** are standard syntax used in DNS (Domain Name System) zone files. In the context of a cybersecurity challenge, this strongly suggested that the flag was stored as a **DNS TXT record** rather than being hidden in the HTML source code or local files.

### 3. Exploitation
To retrieve the hidden record, I performed a DNS query specifically targeting **TXT** records for the domain `ctf.northsec.ma`. 

I used the `nslookup` utility on my Kali Linux environment (the `dig` command would also work effectively here).

**Command:**
```bash
nslookup -type=TXT ctf.northsec.ma
```

**Terminal Output:**
```text
Non-authoritative answer:
ctf.northsec.ma text = "NSC{R1ss4l4_F0UnD_200_TxT_y0Ur_w4Y}"
```

The server responded with a text string containing the flag, confirming that the "unresolved record" mentioned on the UI was indeed a DNS entry.

### 4. Conclusion
The challenge was a classic "Sanity Check" designed to test basic network reconnaissance skills. It required identifying protocol-specific hints within the UI and using command-line tools to query public infrastructure.

**Flag**: `NSC{R1ss4l4_F0UnD_200_TxT_y0Ur_w4Y}`

---

This version looks very professional! Are you ready to move on to a **Web**, **Pwn**, or **Forensics** challenge?
