from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any

from backend.crypto.classical import CaesarCipher, VigenereCipher, MonoalphabeticCipher
from backend.crypto.modern import ModernCryptoEngine

router = APIRouter(prefix="/api/crypto-lab", tags=["Crypto Lab"])

class ClassicalRequest(BaseModel):
    cipher: str # caesar, vigenere, monoalphabetic
    text: str
    key: Optional[str] = "3"
    operation: str = "encrypt" # encrypt or decrypt

class ModernRequest(BaseModel):
    cipher: str # aes, des3, hash
    text: str
    key: Optional[str] = "secret123"
    mode: Optional[str] = "ECB" # ECB or CBC for AES
    algo: Optional[str] = "SHA-256" # for hash

@router.post("/classical")
def execute_classical_cipher(req: ClassicalRequest) -> Dict[str, Any]:
    text = req.text
    key = req.key or ""
    cipher = req.cipher.lower()
    op = req.operation.lower()

    if cipher == "caesar":
        try:
            shift = int(key) if key.isdigit() or (key.startswith('-') and key[1:].isdigit()) else 3
        except Exception:
            shift = 3
        result_text = CaesarCipher.encrypt(text, shift) if op == "encrypt" else CaesarCipher.decrypt(text, shift)
        return {
            "cipher": "Caesar Cipher",
            "operation": op,
            "input": text,
            "key": str(shift),
            "output": result_text,
            "explanation": f"Caesar cipher shifts each letter by {shift} positions in the alphabet. Classical cipher - insecure for real security."
        }

    elif cipher == "vigenere":
        key_str = key if key else "KEY"
        result_text = VigenereCipher.encrypt(text, key_str) if op == "encrypt" else VigenereCipher.decrypt(text, key_str)
        return {
            "cipher": "Vigenere Cipher",
            "operation": op,
            "input": text,
            "key": key_str,
            "output": result_text,
            "explanation": f"Vigenere cipher uses keyword '{key_str}' for polyalphabetic substitution. Classical cipher."
        }

    elif cipher == "monoalphabetic":
        result_text = MonoalphabeticCipher.encrypt(text, key) if op == "encrypt" else MonoalphabeticCipher.decrypt(text, key)
        return {
            "cipher": "Monoalphabetic Substitution Cipher",
            "operation": op,
            "input": text,
            "key": key if key else MonoalphabeticCipher.DEFAULT_KEY,
            "output": result_text,
            "explanation": "Monoalphabetic substitution maps each letter to a fixed key letter. Vulnerable to frequency analysis."
        }

    raise HTTPException(status_code=400, detail="Unsupported classical cipher")

@router.post("/modern")
def execute_modern_cipher(req: ModernRequest) -> Dict[str, Any]:
    cipher = req.cipher.lower()

    if cipher == "aes":
        res = ModernCryptoEngine.aes_encrypt(req.text, req.key or "secret123", req.mode or "ECB", req.operation.lower())
        res["explanation"] = f"AES {req.operation.lower()} using mode {req.mode}. ECB mode is insecure; GCM/CBC mode should be used."
        return res

    elif cipher == "des3":
        res = ModernCryptoEngine.des3_encrypt(req.text, req.key or "secret123", req.operation.lower())
        res["explanation"] = f"Triple DES (3DES) {req.operation.lower()}. Deprecated algorithm due to 64-bit block collision vulnerability (Sweet32)."
        return res

    elif cipher == "hash":
        res = ModernCryptoEngine.compute_hash(req.text, req.algo or "SHA-256")
        res["explanation"] = f"Cryptographic digest using {req.algo}. MD5 and SHA-1 are cryptographically broken."
        return res

    raise HTTPException(status_code=400, detail="Unsupported modern cipher")
