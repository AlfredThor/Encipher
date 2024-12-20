import base64
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    def __init__(self, key: str):
        self.key = self.add_16(key)  # AES 密钥

    def add_16(self, par):
        par = par.encode('utf-8')
        while len(par) % 16 != 0:
            par += b'\x00'
        return par

    @staticmethod
    def string_to_bytes(data: str) -> bytes:
        """将字符串转换为字节"""
        return data.encode('utf-8') if isinstance(data, str) else data

    @staticmethod
    def bytes_to_string(data: bytes) -> str:
        """将字节转换为字符串"""
        return data.decode('utf-8') if isinstance(data, bytes) else data

    def encrypt_ecb(self, plaintext: str) -> str:
        # ECB模式：不需要 IV（不推荐用于安全场景）
        plaintext_bytes = self.string_to_bytes(plaintext)
        cipher = AES.new(self.key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
        return ciphertext.hex()

    def decrypt_ecb(self, ciphertext: str) -> str:
        # ECB模式解密
        ciphertext_bytes = bytes.fromhex(ciphertext)
        cipher = AES.new(self.key, AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
        return self.bytes_to_string(plaintext)

    def encrypt_cbc(self, plaintext: str) -> (str, str):
        # CBC模式: 使用随机生成的 IV
        plaintext_bytes = self.string_to_bytes(plaintext)
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
        return iv.hex(), ciphertext.hex()

    def decrypt_cbc(self, iv: str, ciphertext: str) -> str:
        # CBC模式解密
        iv_bytes = bytes.fromhex(iv)
        ciphertext_bytes = bytes.fromhex(ciphertext)
        cipher = AES.new(self.key, AES.MODE_CBC, iv_bytes)
        plaintext = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
        return self.bytes_to_string(plaintext)

    def encrypt_cfb(self, plaintext: str) -> (str, str):
        plaintext_bytes = self.string_to_bytes(plaintext)
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        ciphertext = cipher.encrypt(plaintext_bytes)
        return iv.hex(), ciphertext.hex()

    def decrypt_cfb(self, iv: str, ciphertext: str) -> str:
        iv_bytes = bytes.fromhex(iv)
        ciphertext_bytes = bytes.fromhex(ciphertext)
        cipher = AES.new(self.key, AES.MODE_CFB, iv_bytes)
        plaintext = cipher.decrypt(ciphertext_bytes)
        return self.bytes_to_string(plaintext)

    def encrypt_ofb(self, plaintext: str) -> (str, str):
        plaintext_bytes = self.string_to_bytes(plaintext)
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_OFB, iv)
        ciphertext = cipher.encrypt(plaintext_bytes)
        return iv.hex(), ciphertext.hex()

    def decrypt_ofb(self, iv: str, ciphertext: str) -> str:
        iv_bytes = bytes.fromhex(iv)
        ciphertext_bytes = bytes.fromhex(ciphertext)
        cipher = AES.new(self.key, AES.MODE_OFB, iv_bytes)
        plaintext = cipher.decrypt(ciphertext_bytes)
        return self.bytes_to_string(plaintext)

    def encrypt_ctr(self, plaintext: str) -> (str, str):
        plaintext_bytes = self.string_to_bytes(plaintext)
        nonce = get_random_bytes(8)
        counter = Counter.new(64, prefix=nonce)
        cipher = AES.new(self.key, AES.MODE_CTR, counter=counter)
        ciphertext = cipher.encrypt(plaintext_bytes)
        return nonce.hex(), ciphertext.hex()

    def decrypt_ctr(self, nonce: str, ciphertext: str) -> str:
        nonce_bytes = bytes.fromhex(nonce)
        ciphertext_bytes = bytes.fromhex(ciphertext)
        counter = Counter.new(64, prefix=nonce_bytes)
        cipher = AES.new(self.key, AES.MODE_CTR, counter=counter)
        plaintext = cipher.decrypt(ciphertext_bytes)
        return self.bytes_to_string(plaintext)


# 示例用法
if __name__ == "__main__":
    # key = get_random_bytes(16)  # 16字节密钥（AES-128）
    key = '486515615154546565'
    aes = AESCipher(key)
    plaintext = "Hello, AES! This is a test message."
    print(plaintext)

    # ECB 模式
    ecb_ciphertext = aes.encrypt_ecb(plaintext)
    ecb_decrypted = aes.decrypt_ecb(ecb_ciphertext)
    print(f"ECB cipher: {ecb_ciphertext}")
    print(f"ECB Decrypted: {ecb_decrypted}")

    # CBC 模式
    iv, cbc_ciphertext = aes.encrypt_cbc(plaintext)
    print(iv)
    print(cbc_ciphertext)
    cbc_decrypted = aes.decrypt_cbc(iv, cbc_ciphertext)
    print(f"CBC Decrypted: {cbc_decrypted}")

    # CFB 模式
    iv, cfb_ciphertext = aes.encrypt_cfb(plaintext)
    cfb_decrypted = aes.decrypt_cfb(iv, cfb_ciphertext)
    print(f"CFB Decrypted: {cfb_decrypted}")

    # OFB 模式
    iv, ofb_ciphertext = aes.encrypt_ofb(plaintext)
    ofb_decrypted = aes.decrypt_ofb(iv, ofb_ciphertext)
    print(f"OFB Decrypted: {ofb_decrypted}")

    # CTR 模式
    nonce, ctr_ciphertext = aes.encrypt_ctr(plaintext)
    ctr_decrypted = aes.decrypt_ctr(nonce, ctr_ciphertext)
    print(f"CTR Decrypted: {ctr_decrypted}")
