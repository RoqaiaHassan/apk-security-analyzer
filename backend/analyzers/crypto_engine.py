import re
from typing import List, Dict, Any, Tuple

class CryptoEngine:
    @staticmethod
    def analyze_crypto_usage(string_records: List[Tuple[str, str, int]]) -> List[Dict[str, Any]]:
        findings = []

        patterns = [
            # AES ECB
            (
                r'AES/ECB',
                "RULE-002",
                "AES ECB Mode Usage",
                "High",
                "AES/ECB",
                "Found Cipher instance with AES/ECB mode in bytecode/strings."
            ),
            # DES
            (
                r'Cipher\.getInstance\s*\(\s*["\']DES["\']|\bDES/CBC|\bDES/ECB',
                "RULE-004",
                "DES Cipher Usage",
                "High",
                "DES",
                "Found Data Encryption Standard (DES) algorithm usage."
            ),
            # 3DES / DESede
            (
                r'DESede|TripleDES|3DES',
                "RULE-005",
                "Triple DES (3DES) Usage",
                "High",
                "3DES/DESede",
                "Found Triple DES cipher usage."
            ),
            # MD5
            (
                r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']|MD5_WITH_RSA|md5',
                "RULE-006",
                "MD5 Hash Algorithm Usage",
                "Medium",
                "MD5",
                "Found MD5 hashing algorithm usage."
            ),
            # SHA-1
            (
                r'MessageDigest\.getInstance\s*\(\s*["\']SHA-1["\']|\bSHA1\b',
                "RULE-007",
                "SHA-1 Hash Algorithm Usage",
                "Medium",
                "SHA-1",
                "Found SHA-1 hashing algorithm usage."
            ),
            # Weak RSA (e.g., 512, 1024)
            (
                r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']\).*\.initialize\s*\(\s*(512|1024)\s*\)',
                "RULE-008",
                "Weak RSA Key Size",
                "High",
                "RSA-1024",
                "Found RSA KeyGenerator initialized with key size < 2048 bits."
            ),
            # Caesar Cipher pattern match
            (
                r'caesar_shift|caesarEncrypt|CaesarCipher|\bshift\s*\+=\s*3\b',
                "RULE-003",
                "Weak or Deprecated Cipher (Caesar)",
                "High",
                "Caesar Cipher",
                "Found Classical Caesar cipher algorithm implementation pattern."
            ),
            # Vigenere Cipher pattern match
            (
                r'VigenereCipher|vigenere_encrypt|vigenereTable',
                "RULE-003",
                "Weak or Deprecated Cipher (Vigenere)",
                "High",
                "Vigenere Cipher",
                "Found Classical Vigenere cipher algorithm implementation pattern."
            ),
            # Monoalphabetic substitution match
            (
                r'Monoalphabetic|substitutionTable|mono_encrypt',
                "RULE-003",
                "Weak or Deprecated Cipher (Monoalphabetic)",
                "High",
                "Monoalphabetic Cipher",
                "Found Classical Monoalphabetic substitution cipher pattern."
            ),
            # Insecure Randomness
            (
                r'Ljava/util/Random;|new Random\(',
                "RULE-012",
                "Insecure Randomness Generator",
                "Medium",
                "java.util.Random",
                "Found java.util.Random used instead of java.security.SecureRandom."
            ),
            # Static IV
            (
                r'IvParameterSpec\s*\(\s*new byte\[\]\s*\{|IvParameterSpec\s*\(\s*["\']',
                "RULE-011",
                "Hardcoded Cryptographic IV",
                "High",
                "Static IV",
                "Found hardcoded static Initialization Vector (IV) byte array."
            )
        ]

        seen_keys = set()

        for file_path, line_content, line_num in string_records:
            for regex, rule_id, title, severity, algo, desc in patterns:
                if re.search(regex, line_content, re.IGNORECASE):
                    key = (rule_id, file_path, line_num)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        findings.append({
                            "rule_id": rule_id,
                            "vulnerability": title,
                            "severity": severity,
                            "category": "Cryptography",
                            "algorithm": algo,
                            "file": file_path,
                            "line": line_num,
                            "evidence": line_content[:120],
                            "description": desc,
                            "status": "DETECTED"
                        })

        return findings
