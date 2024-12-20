from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


class AsymmetricCrypto:

    def __init__(self):
        self.rsa_private_key = None
        self.rsa_public_key = None

        self.ecc_private_key = None
        self.ecc_public_key = None

        self.dsa_private_key = None
        self.dsa_public_key = None

    # RSA 加密与解密
    def generate_rsa_keys(self):
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

    def rsa_encrypt(self, plaintext: str) -> bytes:
        plaintext_bytes = plaintext.encode('utf-8')
        return self.rsa_public_key.encrypt(
            plaintext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def rsa_decrypt(self, ciphertext: bytes) -> str:
        plaintext_bytes = self.rsa_private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext_bytes.decode('utf-8')

    # ECC 签名与验证
    def generate_ecc_keys(self):
        self.ecc_private_key = ec.generate_private_key(ec.SECP256R1())
        self.ecc_public_key = self.ecc_private_key.public_key()

    def ecc_sign(self, message: str) -> bytes:
        message_bytes = message.encode('utf-8')
        return self.ecc_private_key.sign(
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )

    def ecc_verify(self, message: str, signature: bytes) -> bool:
        message_bytes = message.encode('utf-8')
        try:
            self.ecc_public_key.verify(
                signature,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False

    # DSA 签名与验证
    def generate_dsa_keys(self):
        self.dsa_private_key = dsa.generate_private_key(key_size=2048)
        self.dsa_public_key = self.dsa_private_key.public_key()

    def dsa_sign(self, message: str) -> bytes:
        message_bytes = message.encode('utf-8')
        return self.dsa_private_key.sign(
            message_bytes,
            hashes.SHA256()
        )

    def dsa_verify(self, message: str, signature: bytes) -> bool:
        message_bytes = message.encode('utf-8')
        try:
            self.dsa_public_key.verify(
                signature,
                message_bytes,
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


# 示例用法
if __name__ == "__main__":
    crypto = AsymmetricCrypto()

    # RSA 加密与解密
    crypto.generate_rsa_keys()
    rsa_message = "Hello, RSA!"
    rsa_encrypted = crypto.rsa_encrypt(rsa_message)
    rsa_decrypted = crypto.rsa_decrypt(rsa_encrypted)
    print(f"RSA Encrypted: {rsa_encrypted}")
    print(f"RSA Decrypted: {rsa_decrypted}")

    # ECC 签名与验证
    crypto.generate_ecc_keys()
    ecc_message = "Hello, ECC!"
    ecc_signature = crypto.ecc_sign(ecc_message)
    ecc_valid = crypto.ecc_verify(ecc_message, ecc_signature)
    print(f"ECC Signature: {ecc_signature}")
    print(f"ECC Valid: {ecc_valid}")

    # DSA 签名与验证
    crypto.generate_dsa_keys()
    dsa_message = "Hello, DSA!"
    dsa_signature = crypto.dsa_sign(dsa_message)
    dsa_valid = crypto.dsa_verify(dsa_message, dsa_signature)
    print(f"DSA Signature: {dsa_signature}")
    print(f"DSA Valid: {dsa_valid}")
