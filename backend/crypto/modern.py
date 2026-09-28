import base64
import hashlib
from typing import Dict, Any

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class ModernCryptoEngine:
    @staticmethod
    def aes_encrypt(plaintext: str, key_str: str, mode_name: str = "ECB", operation: str = "encrypt") -> Dict[str, Any]:
        if not CRYPTO_AVAILABLE:
            return {"error": "cryptography library not installed"}

        key = hashlib.sha256(key_str.encode()).digest()[:16]  # 128-bit key
        iv = b"1234567890123456"

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        if mode_name.upper() == "ECB":
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        else:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        if operation == "decrypt":
            try:
                ciphertext = base64.b64decode(plaintext.encode("ascii"), validate=True)
                decryptor = cipher.decryptor()
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                unpadder = padding.PKCS7(128).unpadder()
                decrypted = unpadder.update(padded_plaintext) + unpadder.finalize()
                return {
                    "algorithm": f"AES-128 ({mode_name.upper()})",
                    "operation": "decrypt",
                    "ciphertext_base64": plaintext,
                    "decrypted_plaintext": decrypted.decode("utf-8"),
                    "key_hex": key.hex(),
                    "iv_hex": iv.hex() if mode_name.upper() == "CBC" else "N/A (ECB Mode)"
                }
            except (ValueError, UnicodeDecodeError) as exc:
                return {"error": f"Invalid AES ciphertext or key: {exc}"}

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return {
            "algorithm": f"AES-128 ({mode_name.upper()})",
            "key_hex": key.hex(),
            "iv_hex": iv.hex() if mode_name.upper() == "CBC" else "N/A (ECB Mode)",
            "ciphertext_base64": base64.b64encode(ciphertext).decode()
        }

    @staticmethod
    def des3_encrypt(plaintext: str, key_str: str, operation: str = "encrypt") -> Dict[str, Any]:
        if not CRYPTO_AVAILABLE:
            return {"error": "cryptography library not installed"}

        key = hashlib.md5(key_str.encode()).digest() + hashlib.md5(key_str.encode()).digest()[:8] # 24 bytes
        iv = b"12345678"

        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        if operation == "decrypt":
            try:
                ciphertext = base64.b64decode(plaintext.encode("ascii"), validate=True)
                decryptor = cipher.decryptor()
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                unpadder = padding.PKCS7(64).unpadder()
                decrypted = unpadder.update(padded_plaintext) + unpadder.finalize()
                return {
                    "algorithm": "Triple DES (3DES/CBC)",
                    "operation": "decrypt",
                    "ciphertext_base64": plaintext,
                    "decrypted_plaintext": decrypted.decode("utf-8"),
                    "key_hex": key.hex(),
                    "iv_hex": iv.hex()
                }
            except (ValueError, UnicodeDecodeError) as exc:
                return {"error": f"Invalid 3DES ciphertext or key: {exc}"}

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return {
            "algorithm": "Triple DES (3DES/CBC)",
            "key_hex": key.hex(),
            "iv_hex": iv.hex(),
            "ciphertext_base64": base64.b64encode(ciphertext).decode()
        }

    @staticmethod
    def compute_hash(plaintext: str, algo: str = "SHA-256") -> Dict[str, Any]:
        data = plaintext.encode('utf-8')
        algo = algo.upper()

        if algo == "MD5":
            digest = hashlib.md5(data).hexdigest()
        elif algo == "SHA-1":
            digest = hashlib.sha1(data).hexdigest()
        elif algo == "SHA-512":
            digest = hashlib.sha512(data).hexdigest()
        elif algo == "SHA3-256":
            digest = hashlib.sha3_256(data).hexdigest()
        else:
            digest = hashlib.sha256(data).hexdigest()

        return {
            "algorithm": algo,
            "input": plaintext,
            "hash_hex": digest
        }
