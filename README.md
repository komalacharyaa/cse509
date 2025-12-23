# CSE 509 – Computer System Security  
**Homework Assignments Repository**

This repository contains my homework submissions for [**CSE 509: Computer System Security**](https://www.cs.stonybrook.edu/students/graduate-studies/courses/cse509).  
Each assignment focuses on hands-on system security concepts such as exploitation, cryptographic protocols, and reverse engineering.

---

## Homework 1: Buffer Overflow Exploitation

### Objective
The goal of this assignment is to **identify vulnerabilities** in vulnerable C programs and **develop working exploits** that escalate privileges to gain a root shell.

### What I Did
- Analyzed three vulnerable binaries (`target1`, `target2`, `target3`)
- Identified security flaws such as:
  - Buffer overflows
  - Off-by-one errors
  - Arithmetic overflows
- Crafted custom exploits (`xploit1`, `xploit2`, `xploit3`)
- Executed exploits as an unprivileged user to obtain **root access**
- Used debugging tools to analyze stack layout and control flow

### Key Concepts
- Stack memory layout
- Instruction pointer (IP) control
- Shellcode injection
- Setuid binaries
- Exploit reliability

### Tools & Technologies
- **C**
- **GDB**
- **QEMU (Debian VM)**
- **GCC**
- **Linux system calls**
- **Shellcode**

---

## Homework 2: Private Set Intersection (PSI) using Oblivious Transfer

### Objective
The goal of this assignment is to implement a **two-party Private Set Intersection (PSI)** protocol using a **1-out-of-2 Oblivious Transfer (1/2 OT)** primitive.

### What I Did
- Implemented the PSI protocol logic in `psi.py`
- Used **ElGamal public-key cryptography** to build the OT primitive
- Modeled Alice (client) and Bob (server) interaction securely
- Performed a **bitwise private equality test** for each item
- Ensured neither party learns anything beyond the final intersection

### Key Concepts
- Oblivious Transfer (1/2 OT)
- Private Equality Testing
- Secure two-party computation
- Public-key cryptography
- XOR-based masking

### Tools & Technologies
- **Python 3.12**
- **ElGamal cryptosystem**
- **elgamal Python library**
- **uv (Python environment manager)**
- **QEMU virtual machine**

---

## Homework 3: Reverse Engineering & Binary Patching

### Objective
The goal of this assignment is to **reverse-engineer compiled binaries**, recover hidden passwords, and **bypass authentication logic** using binary patching.

### What I Did
- Reverse-engineered two password-protected binaries:
  - `crackme1`: recovered hard-coded password
  - `crackme2`: reconstructed obfuscated password logic
- Analyzed assembly and decompiled code
- Patched the binary to bypass authentication checks without knowing the password
- Verified behavior using a VM

### Key Concepts
- Static binary analysis
- String recovery
- Obfuscation reversal
- Control-flow manipulation
- Binary patching

### Tools & Technologies
- **Ghidra**
- **x86 Assembly**
- **QEMU virtual machine**
- **Java (for Ghidra runtime)**
- **Linux ELF binaries**

---

## Disclaimer
All work in this repository was performed **strictly for educational purposes** as part of a university course.  
The techniques demonstrated here should **only be used in legal and ethical environments** such as coursework, labs, or security research.

---

## Author
**Komalika Acharya**  
MS in Computer Science  
Stony Brook University
