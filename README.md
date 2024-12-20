
## **[English](https://github.com/AlfredThor/Encipher)** **[中文](https://github.com/AlfredThor/Encipher/blob/master/README_CN.md)**

---

## Basic concept

- Encryption: Converts plaintext data to ciphertext that cannot be read directly.
- Decryption: Restore ciphertext to plain text.
- Algorithm: A mathematical formula or method for encryption and decryption.
- Key: A key part of encryption and decryption, security depends on the confidentiality of the key.

---

## Common Encryption Methods

### One-Way Encryption

> Data encrypted using one-way encryption cannot be reversed. It is commonly used for password storage. The same 
> input produces the same output, and it is impossible to deduce the input from the output.

#### Common One-Way Encryption Algorithms

- MD5 (Not recommended, vulnerable to collision attacks)
- SHA-1 (Not recommended, insufficient security)
- SHA-256 / SHA-3 (More secure options)
- Argon2 (Currently the most recommended password hashing algorithm, strong resistance to GPU attacks)

### Symmetric Encryption

> The same key is used for both encryption and decryption. It is efficient but has complex key management challenges.

#### Common Algorithms

- AES (Advanced Encryption Standard, recommended)
- DES (Triple DES is no longer recommended)

### Asymmetric Encryption

> Encryption and decryption use different keys: a Public Key and a Private Key. There is no need to share the key, ensuring high security, though it is slower.

#### Common Algorithms

- RSA
- ECC(Elliptic Curve Cryptography)
- DSA(Digital Signature Algorithm)

---