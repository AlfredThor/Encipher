# python3AES-
AES symmetrical encryption

### 使用方式如下

```python
if __name__ == '__main__':
    pattern_ecb = aescrypt('123478596','ECB','','utf8')
    en_text = pattern_ecb.aesencrypt('My hero')
    print('ECB加密模式密文:',en_text)
    data = pattern_ecb.aesdecrypt('t7Amf9fH6H+0YOAsNLOKeA==')
    print('ECB加密模式明文：',data)

    pattern_cbc = aescrypt('859685','CBC','1252635241524152','utf8')
    cbc_text = pattern_cbc.aesencrypt('My hero')
    print('CBC加密模式密文：',cbc_text)
    cbc_data = pattern_cbc.aesdecrypt(cbc_text)
    print('CBC加密模式密文：',cbc_data)
```

---

## Basic concept

- Encryption: Converts plaintext data to ciphertext that cannot be read directly.
- Decryption: Restore ciphertext to plain text.
- Algorithm: A mathematical formula or method for encryption and decryption.
- Key: A key part of encryption and decryption, security depends on the confidentiality of the key.