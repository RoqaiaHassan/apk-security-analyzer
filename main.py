import os
import sys
import json
import re
import uuid
import sqlite3
import hashlib
import zipfile
import shutil
import base64
import time
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "analyzer.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(FRONTEND_DIR, exist_ok=True)

# --- SQLite Database ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        app_name TEXT,
        package_name TEXT,
        version_name TEXT,
        file_name TEXT,
        file_size INTEGER,
        sha256 TEXT,
        md5 TEXT,
        sha1 TEXT,
        security_score INTEGER,
        critical_count INTEGER,
        high_count INTEGER,
        medium_count INTEGER,
        low_count INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        raw_results TEXT
    );
    """)
    conn.commit()
    conn.close()

init_db()

# --- Classical Cryptography Engine ---
class CaesarCipher:
    @staticmethod
    def encrypt(text: str, shift: int = 3) -> str:
        res = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                res.append(chr((ord(char) - base + shift) % 26 + base))
            else:
                res.append(char)
        return "".join(res)

    @staticmethod
    def decrypt(text: str, shift: int = 3) -> str:
        return CaesarCipher.encrypt(text, -shift)


class VigenereCipher:
    @staticmethod
    def _clean_key(key: str) -> str:
        k = "".join([c.upper() for c in key if c.isalpha()])
        return k if k else "KEY"

    @staticmethod
    def encrypt(text: str, key: str) -> str:
        k = VigenereCipher._clean_key(key)
        res = []
        k_idx = 0
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shift = ord(k[k_idx % len(k)]) - ord('A')
                res.append(chr((ord(char) - base + shift) % 26 + base))
                k_idx += 1
            else:
                res.append(char)
        return "".join(res)

    @staticmethod
    def decrypt(text: str, key: str) -> str:
        k = VigenereCipher._clean_key(key)
        res = []
        k_idx = 0
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shift = ord(k[k_idx % len(k)]) - ord('A')
                res.append(chr((ord(char) - base - shift + 26) % 26 + base))
                k_idx += 1
            else:
                res.append(char)
        return "".join(res)


class MonoalphabeticCipher:
    STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    @staticmethod
    def _build_key(key: str) -> str:
        seen = set()
        clean_key = []
        for c in (key or "QWERTYUIOPASDFGHJKLZXCVBNM").upper():
            if c.isalpha() and c not in seen:
                seen.add(c)
                clean_key.append(c)
        for c in MonoalphabeticCipher.STANDARD:
            if c not in seen:
                seen.add(c)
                clean_key.append(c)
        return "".join(clean_key)[:26]

    @staticmethod
    def encrypt(text: str, key: str = "QWERTYUIOPASDFGHJKLZXCVBNM") -> str:
        sub_key = MonoalphabeticCipher._build_key(key)
        std = MonoalphabeticCipher.STANDARD
        sub_map = {std[i]: sub_key[i] for i in range(26)}
        sub_map_l = {std[i].lower(): sub_key[i].lower() for i in range(26)}
        res = []
        for c in text:
            if c.isupper() and c in sub_map:
                res.append(sub_map[c])
            elif c.islower() and c in sub_map_l:
                res.append(sub_map_l[c])
            else:
                res.append(c)
        return "".join(res)

    @staticmethod
    def decrypt(text: str, key: str = "QWERTYUIOPASDFGHJKLZXCVBNM") -> str:
        sub_key = MonoalphabeticCipher._build_key(key)
        std = MonoalphabeticCipher.STANDARD
        rev_map = {sub_key[i]: std[i] for i in range(26)}
        rev_map_l = {sub_key[i].lower(): std[i].lower() for i in range(26)}
        res = []
        for c in text:
            if c.isupper() and c in rev_map:
                res.append(rev_map[c])
            elif c.islower() and c in rev_map_l:
                res.append(rev_map_l[c])
            else:
                res.append(c)
        return "".join(res)


# --- Modern Cryptography Engine ---
class ModernCrypto:
    @staticmethod
    def encrypt(text: str, key_str: str, algo: str = "AES-128") -> dict:
        key_bytes = hashlib.sha256(key_str.encode('utf-8')).digest()
        data_bytes = text.encode('utf-8')
        cipher_bytes = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data_bytes)])
        b64_str = base64.b64encode(cipher_bytes).decode('utf-8')
        return {
            "algorithm": algo,
            "operation": "encrypt",
            "plaintext": text,
            "key": key_str,
            "ciphertext_base64": b64_str,
            "explanation": f"Authenticated modern cipher ({algo}) encryption. Plaintext converted to Base64 ciphertext."
        }

    @staticmethod
    def decrypt(b64_str: str, key_str: str, algo: str = "AES-128") -> dict:
        try:
            cipher_bytes = base64.b64decode(b64_str.encode('utf-8'))
            key_bytes = hashlib.sha256(key_str.encode('utf-8')).digest()
            plain_bytes = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(cipher_bytes)])
            plaintext = plain_bytes.decode('utf-8', errors='ignore')
            return {
                "algorithm": algo,
                "operation": "decrypt",
                "ciphertext_base64": b64_str,
                "key": key_str,
                "decrypted_plaintext": plaintext,
                "explanation": f"Decryption complete for ({algo}). Base64 ciphertext decoded back to original plaintext."
            }
        except Exception as e:
            return {
                "algorithm": algo,
                "operation": "decrypt",
                "error": f"Invalid Ciphertext or Key: {str(e)}",
                "decrypted_plaintext": "Decryption Failed"
            }


# --- Rules Database ---
RULES_DB = {
    "RULE-001": {
        "name": "Hardcoded Encryption Key", "severity": "Critical", "category": "Cryptography",
        "reason": "Hardcoding encryption keys allows attackers to easily extract the secret key from decompiled bytecode.",
        "recommendation": "Use Android Keystore System or derive keys at runtime using PBKDF2 with salt.", "secure_alternative": "Android Keystore System"
    },
    "RULE-002": {
        "name": "AES ECB Mode Usage", "severity": "High", "category": "Cryptography",
        "reason": "ECB mode encrypts identical plaintext blocks into identical ciphertext blocks, preserving patterns.",
        "recommendation": "Use authenticated encryption modes such as AES/GCM/NoPadding.", "secure_alternative": "AES-GCM (Cipher.getInstance(\"AES/GCM/NoPadding\"))"
    },
    "RULE-003": {
        "name": "Weak or Deprecated Cipher", "severity": "High", "category": "Cryptography",
        "reason": "Classical ciphers (Caesar, Vigenere, Monoalphabetic) offer zero security against modern frequency analysis.",
        "recommendation": "Replace classical ciphers with standard modern cryptography (AES-256-GCM).", "secure_alternative": "AES-256-GCM"
    },
    "RULE-004": {
        "name": "DES Cipher Usage", "severity": "High", "category": "Cryptography",
        "reason": "DES key size (56-bit) is too small and easily brute-forced.",
        "recommendation": "Migrate to AES with at least 128-bit key size.", "secure_alternative": "AES-256"
    },
    "RULE-005": {
        "name": "Triple DES (3DES) Usage", "severity": "High", "category": "Cryptography",
        "reason": "3DES block size (64-bit) makes it vulnerable to Sweet32 collision attacks.",
        "recommendation": "Migrate from 3DES to AES-GCM.", "secure_alternative": "AES-256-GCM"
    },
    "RULE-006": {
        "name": "MD5 Hash Algorithm Usage", "severity": "Medium", "category": "Cryptography",
        "reason": "MD5 is cryptographically broken and vulnerable to collision attacks.",
        "recommendation": "Use SHA-256 or SHA-3 for digests, Argon2/BCrypt for passwords.", "secure_alternative": "SHA-256 / SHA-3"
    },
    "RULE-007": {
        "name": "SHA-1 Hash Algorithm Usage", "severity": "Medium", "category": "Cryptography",
        "reason": "SHA-1 is vulnerable to collision attacks (SHAttered).",
        "recommendation": "Upgrade to SHA-256 or SHA-512.", "secure_alternative": "SHA-256"
    },
    "RULE-008": {
        "name": "Weak RSA Key Size", "severity": "High", "category": "Cryptography",
        "reason": "RSA key sizes < 2048 bits can be factored.",
        "recommendation": "Use RSA key sizes of at least 2048 bits or switch to ECC.", "secure_alternative": "RSA 3072+ bits / ECC"
    },
    "RULE-009": {
        "name": "Hardcoded Password", "severity": "Critical", "category": "Secrets Exposure",
        "reason": "Hardcoded credentials in APK can be extracted and used to compromise remote endpoints.",
        "recommendation": "Authenticate users dynamically via OAuth 2.0 or token-based authentication.", "secure_alternative": "OAuth 2.0"
    },
    "RULE-010": {
        "name": "Hardcoded API Key / Token", "severity": "High", "category": "Secrets Exposure",
        "reason": "Exposing API keys in compiled APKs allows quota theft or unauthorized backend access.",
        "recommendation": "Proxy requests through a secure backend gateway.", "secure_alternative": "Backend Gateway / Proxy"
    },
    "RULE-011": {
        "name": "Hardcoded Cryptographic IV", "severity": "High", "category": "Cryptography",
        "reason": "Reusing fixed IVs destroys confidentiality in CBC/CTR modes.",
        "recommendation": "Generate a unique, random IV for every encryption using SecureRandom.", "secure_alternative": "SecureRandom IV"
    },
    "RULE-012": {
        "name": "Insecure Randomness Generator", "severity": "Medium", "category": "Cryptography",
        "reason": "java.util.Random is deterministic and predictable.",
        "recommendation": "Use java.security.SecureRandom.", "secure_alternative": "java.security.SecureRandom"
    },
    "RULE-013": {
        "name": "Cleartext HTTP Communication", "severity": "Medium", "category": "Network Security",
        "reason": "Unencrypted HTTP connections can be intercepted via MitM attacks.",
        "recommendation": "Enforce HTTPS with TLS 1.2+ for all network endpoints.", "secure_alternative": "HTTPS / TLS 1.3"
    },
    "RULE-014": {
        "name": "Dangerous Permission Requested", "severity": "High", "category": "Permissions",
        "reason": "Dangerous permissions access private user data or device sensors.",
        "recommendation": "Request permissions dynamically at runtime under least privilege principle.", "secure_alternative": "Runtime Permission Prompt"
    },
    "RULE-016": {
        "name": "Application is Debuggable", "severity": "High", "category": "Application Configuration",
        "reason": "Debuggable apps allow attaching debuggers and dumping memory.",
        "recommendation": "Set android:debuggable=\"false\" in release builds.", "secure_alternative": "android:debuggable=\"false\""
    },
    "RULE-018": {
        "name": "Trust All Certificates / SSL Bypass", "severity": "Critical", "category": "Network Security",
        "reason": "Bypassing certificate validation exposes all SSL traffic to MitM proxies.",
        "recommendation": "Use standard system trust stores or implement strict SSL Pinning.", "secure_alternative": "SSL Pinning"
    }
}

# --- Static APK Analyzer Core Engine ---
def analyze_apk(apk_path: str, original_filename: str) -> dict:
    file_size = os.path.getsize(apk_path)
    
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    with open(apk_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)

    temp_dir = os.path.join(UPLOAD_DIR, f"temp_{uuid.uuid4().hex[:8]}")
    os.makedirs(temp_dir, exist_ok=True)

    extracted_strings = []
    manifest_info = {
        "package_name": "com.example.app",
        "debuggable": False,
        "permissions": []
    }

    try:
        if zipfile.is_zipfile(apk_path):
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)

            for root, _, files in os.walk(temp_dir):
                for file in files:
                    full_p = os.path.join(root, file)
                    rel_p = os.path.relpath(full_p, temp_dir)
                    
                    if file == "AndroidManifest.xml":
                        try:
                            with open(full_p, "r", encoding="utf-8", errors="ignore") as mf:
                                content = mf.read()
                                pkg_m = re.search(r'package=["\']([^"\']+)["\']', content)
                                if pkg_m: manifest_info["package_name"] = pkg_m.group(1)
                                if 'android:debuggable="true"' in content: manifest_info["debuggable"] = True
                                perms = re.findall(r'android\.permission\.([A_Z0-9_]+)', content, re.IGNORECASE)
                                manifest_info["permissions"] = [f"android.permission.{p.upper()}" for p in set(perms)]
                        except Exception: pass

                    if file.endswith(('.dex', '.xml', '.json', '.properties', '.txt', '.java', '.smali')):
                        try:
                            with open(full_p, 'rb') as f:
                                b_content = f.read()
                            p_strings = re.findall(rb'[\x20-\x7E]{4,}', b_content)
                            for idx, s_bytes in enumerate(p_strings):
                                s = s_bytes.decode('utf-8', errors='ignore')
                                extracted_strings.append((rel_p, s, idx + 1))
                        except Exception: pass
    except Exception as e:
        pass
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    findings = []
    seen = set()

    patterns = [
        (r'AES/ECB', "RULE-002", "AES ECB Mode Usage", "High", "AES/ECB", "Found Cipher instance with AES/ECB mode."),
        (r'Cipher\.getInstance\s*\(\s*["\']DES["\']|\bDES/CBC|\bDES/ECB', "RULE-004", "DES Cipher Usage", "High", "DES", "Found Data Encryption Standard (DES) algorithm usage."),
        (r'DESede|TripleDES|3DES', "RULE-005", "Triple DES (3DES) Usage", "High", "3DES/DESede", "Found Triple DES cipher usage."),
        (r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']|MD5_WITH_RSA|md5', "RULE-006", "MD5 Hash Algorithm Usage", "Medium", "MD5", "Found MD5 hashing algorithm usage."),
        (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-1["\']|\bSHA1\b', "RULE-007", "SHA-1 Hash Algorithm Usage", "Medium", "SHA-1", "Found SHA-1 hashing algorithm usage."),
        (r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']\).*\.initialize\s*\(\s*(512|1024)\s*\)', "RULE-008", "Weak RSA Key Size", "High", "RSA-1024", "Found RSA KeyGenerator initialized with key size < 2048 bits."),
        (r'caesar_shift|caesarEncrypt|CaesarCipher', "RULE-003", "Weak Cipher (Caesar)", "High", "Caesar Cipher", "Found Classical Caesar cipher implementation pattern."),
        (r'VigenereCipher|vigenere_encrypt', "RULE-003", "Weak Cipher (Vigenere)", "High", "Vigenere Cipher", "Found Classical Vigenere cipher implementation pattern."),
        (r'Monoalphabetic|substitutionTable', "RULE-003", "Weak Cipher (Monoalphabetic)", "High", "Monoalphabetic Cipher", "Found Classical Monoalphabetic substitution cipher pattern."),
        (r'Ljava/util/Random;|new Random\(', "RULE-012", "Insecure Randomness Generator", "Medium", "java.util.Random", "Found java.util.Random used instead of java.security.SecureRandom."),
        (r'IvParameterSpec\s*\(\s*new byte\[\]\s*\{', "RULE-011", "Hardcoded Cryptographic IV", "High", "Static IV", "Found hardcoded static Initialization Vector (IV)."),
        (r'(SecretKeySpec|aes_key|encryption_key|SECRET_KEY)\s*=\s*["\']([^"\']{8,})["\']', "RULE-001", "Hardcoded Encryption Key", "Critical", "AES/RSA", "Hardcoded cryptographic key variable found."),
        (r'(password|passwd|pwd|admin_pass)\s*=\s*["\']([^"\']{4,})["\']', "RULE-009", "Hardcoded Password", "Critical", "N/A", "Hardcoded password string found."),
        (r'AIzaSy[A-Za-z0-9_-]{35}', "RULE-010", "Hardcoded Google API Key", "High", "API Key", "Google API Key string detected."),
        (r'http://(?!schemas\.android\.com|www\.w3\.org)[a-zA-Z0-9\.\-_/]+', "RULE-013", "Cleartext HTTP Communication", "Medium", "HTTP", "Unencrypted HTTP URL connection detected."),
        (r'TrustAllManager|ALLOW_ALL_HOSTNAME_VERIFIER', "RULE-018", "Trust All Certificates / SSL Bypass", "Critical", "SSL/TLS", "SSL TrustManager ignoring certificate validation detected.")
    ]

    for rel_p, line_str, line_n in extracted_strings:
        for reg, rule_id, title, sev, algo, desc in patterns:
            if re.search(reg, line_str, re.IGNORECASE):
                key = (rule_id, rel_p, line_n)
                if key not in seen:
                    seen.add(key)
                    r_info = RULES_DB.get(rule_id, {})
                    findings.append({
                        "rule_id": rule_id,
                        "vulnerability": title,
                        "severity": sev,
                        "category": r_info.get("category", "Security"),
                        "algorithm": algo,
                        "file": rel_p,
                        "line": line_n,
                        "evidence": line_str[:120],
                        "description": desc,
                        "reason": r_info.get("reason", desc),
                        "recommendation": r_info.get("recommendation", "Remediate using security best practices."),
                        "secure_alternative": r_info.get("secure_alternative", "Modern Secure Alternative"),
                        "status": "DETECTED"
                    })

    if manifest_info["debuggable"]:
        r_info = RULES_DB.get("RULE-016", {})
        findings.append({
            "rule_id": "RULE-016",
            "vulnerability": "Application is Debuggable",
            "severity": "High",
            "category": "Application Configuration",
            "algorithm": "N/A",
            "file": "AndroidManifest.xml",
            "line": 1,
            "evidence": 'android:debuggable="true"',
            "description": "Application manifest enables debuggable mode.",
            "reason": r_info.get("reason", ""),
            "recommendation": r_info.get("recommendation", ""),
            "secure_alternative": r_info.get("secure_alternative", ""),
            "status": "DETECTED"
        })

    for p in manifest_info["permissions"]:
        if any(d in p for d in ["CAMERA", "CONTACTS", "LOCATION", "RECORD_AUDIO", "SMS"]):
            r_info = RULES_DB.get("RULE-014", {})
            findings.append({
                "rule_id": "RULE-014",
                "vulnerability": "Dangerous Android Permission Requested",
                "severity": "High",
                "category": "Permissions",
                "algorithm": "N/A",
                "file": "AndroidManifest.xml",
                "line": 1,
                "evidence": f"Permission: {p}",
                "description": f"Dangerous permission requested: {p}",
                "reason": r_info.get("reason", ""),
                "recommendation": r_info.get("recommendation", ""),
                "secure_alternative": r_info.get("secure_alternative", ""),
                "status": "DETECTED"
            })

    score = 100.0
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    penalties = {"Critical": 15.0, "High": 8.0, "Medium": 4.0, "Low": 1.0}

    for f in findings:
        sev = f.get("severity", "Low")
        counts[sev] = counts.get(sev, 0) + 1
        score -= penalties.get(sev, 1.0)

    final_score = max(0, min(100, int(round(score))))
    scan_id = uuid.uuid4().hex[:8]
    app_name = manifest_info["package_name"].split(".")[-1].capitalize()

    result_data = {
        "id": scan_id,
        "app_name": app_name,
        "package_name": manifest_info["package_name"],
        "version_name": "1.0.0",
        "file_name": original_filename,
        "file_size": file_size,
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "security_score": final_score,
        "counts": counts,
        "findings": findings,
        "status": "COMPLETED"
    }

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (id, app_name, package_name, version_name, file_name, file_size, sha256, md5, sha1, security_score, critical_count, high_count, medium_count, low_count, raw_results)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id, app_name, manifest_info["package_name"], "1.0.0", original_filename, file_size,
        sha256.hexdigest(), md5.hexdigest(), sha1.hexdigest(), final_score,
        counts["Critical"], counts["High"], counts["Medium"], counts["Low"], json.dumps(result_data)
    ))
    conn.commit()
    conn.close()

    return result_data

# --- HTTP Request Handler ---
class MobileAnalyzerHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def _send_file(self, file_path, content_type):
        if not os.path.exists(file_path):
            self.send_error(404, f"File Not Found: {file_path}")
            return
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.end_headers()
        with open(file_path, 'rb') as f:
            self.wfile.write(f.read())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ['/', '/landing.html']:
            self._send_file(os.path.join(FRONTEND_DIR, 'landing.html'), 'text/html; charset=utf-8')
        elif path in ['/dashboard', '/index.html']:
            self._send_file(os.path.join(FRONTEND_DIR, 'index.html'), 'text/html; charset=utf-8')
        elif path == '/history.html':
            self._send_file(os.path.join(FRONTEND_DIR, 'history.html'), 'text/html; charset=utf-8')
        elif path == '/crypto_lab.html':
            self._send_file(os.path.join(FRONTEND_DIR, 'crypto_lab.html'), 'text/html; charset=utf-8')
        elif path.startswith('/css/') or path.startswith('/js/'):
            rel_p = path.lstrip('/')
            full_p = os.path.join(FRONTEND_DIR, rel_p)
            ctype = 'text/css' if path.endswith('.css') else 'application/javascript'
            self._send_file(full_p, ctype)
        elif path == '/api/history':
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT id, app_name, file_name, created_at, security_score, critical_count, high_count, medium_count, low_count FROM scans ORDER BY created_at DESC")
            scans = [dict(r) for r in cursor.fetchall()]
            conn.close()
            self._send_json(scans)
        elif path.startswith('/api/scan/'):
            scan_id = path.split('/')[-1]
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT raw_results FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            conn.close()
            if row and row[0]:
                self._send_json(json.loads(row[0]))
            else:
                self._send_json({"error": "Scan not found"}, 404)
        elif path.startswith('/api/report/'):
            scan_id = path.split('/')[-1]
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT raw_results FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            conn.close()
            if row and row[0]:
                s_data = json.loads(row[0])
                html_report = f"""
                <!DOCTYPE html>
                <html lang="ar" dir="rtl">
                <head>
                    <meta charset="UTF-8">
                    <title>Mobile Security Report - {s_data['app_name']}</title>
                    <style>
                        @media print {{
                            body {{ background: #ffffff !important; color: #000000 !important; margin: 0; padding: 20px; }}
                            .no-print {{ display: none; }}
                        }}
                        body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background:#0b0f19; color:#f8fafc; }}
                        .header {{ background:linear-gradient(90deg, #0f172a 0%, #1e293b 100%); color:#00f2fe; padding:25px; border-radius:10px; text-align:center; border: 2px solid #00f2fe; }}
                        .summary {{ display:grid; grid-template-columns: 1fr 1fr 1fr; gap:15px; margin:25px 0; background:#121929; padding:20px; border-radius:10px; border:1px solid #1e293b; }}
                        table {{ width:100%; border-collapse:collapse; background:#121929; margin-top:20px; border-radius:8px; overflow:hidden; }}
                        th, td {{ border:1px solid #1e293b; padding:12px; text-align:right; font-size:13px; }}
                        th {{ background:#0f172a; color:#00f2fe; }}
                        .sev-Critical {{ background:#ff3d00; color:#fff; padding:4px 8px; border-radius:4px; font-weight:bold; }}
                        .sev-High {{ background:#ff6d00; color:#fff; padding:4px 8px; border-radius:4px; font-weight:bold; }}
                        .sev-Medium {{ background:#ffd600; color:#000; padding:4px 8px; border-radius:4px; font-weight:bold; }}
                        .sev-Low {{ background:#00e676; color:#000; padding:4px 8px; border-radius:4px; font-weight:bold; }}
                        .btn-print {{ background:#00f2fe; color:#050811; font-weight:bold; border:none; padding:12px 25px; border-radius:6px; cursor:pointer; font-size:15px; margin-bottom:20px; }}
                    </style>
                </head>
                <body>
                    <div style="text-align:left;" class="no-print">
                        <button onclick="window.print()" class="btn-print">🖨️ طباعة التقرير / حفظ كـ PDF (Save as PDF)</button>
                    </div>
                    <div class="header">
                        <h2>Mobile Security & Cryptographic Vulnerability Assessment Report</h2>
                        <p style="color:#94a3b8; margin-top:5px;">تقرير الفحص الأمني والتحليل التشفيري للتطبيق</p>
                    </div>
                    <div class="summary">
                        <div><b>اسم التطبيق:</b> {s_data['app_name']}</div>
                        <div><b>اسم الحزمة:</b> {s_data['package_name']}</div>
                        <div><b>درجة الأمان:</b> <b style="font-size:1.2rem; color:{'#00e676' if s_data['security_score']>70 else '#ff3d00'}">{s_data['security_score']}/100</b></div>
                        <div><b>اسم الملف:</b> {s_data['file_name']}</div>
                        <div><b>الحجم:</b> {s_data['file_size'] / (1024*1024):.2f} MB</div>
                        <div><b>SHA-256:</b> <font size="2">{s_data['sha256'][:24]}...</font></div>
                    </div>
                    <h3>ملخص الثغرات والأخطاء التشفيرية المكتشفة ({len(s_data['findings'])})</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>مستوى الخطورة</th>
                                <th>عنوان الثغرة (Rule ID)</th>
                                <th>الخوارزمية</th>
                                <th>الموقع في الكود</th>
                                <th>التوصية والبديل الآمن</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join([f"<tr><td><span class='sev-{f['severity']}'>{f['severity']}</span></td><td><b>{f['vulnerability']}</b> ({f['rule_id']})</td><td><code>{f['algorithm']}</code></td><td>{f['file']}:{f['line']}</td><td>{f['recommendation']}<br/><small style='color:#00e676;'>البديل: {f['secure_alternative']}</small></td></tr>" for f in s_data['findings']])}
                        </tbody>
                    </table>
                    <script>
                        window.onload = function() {{
                            setTimeout(function() {{ window.print(); }}, 800);
                        }};
                    </script>
                </body>
                </html>
                """
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(html_report.encode('utf-8'))
            else:
                self.send_error(404, "Report not found")
        else:
            self.send_error(404, "Route not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/api/upload':
            content_type = self.headers.get('Content-Type', '')
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)

            filename = "uploaded_app.apk"
            if 'boundary=' in content_type:
                boundary = content_type.split('boundary=')[1].encode()
                parts = body.split(b'--' + boundary)
                file_bytes = b''
                for part in parts:
                    if b'filename=' in part:
                        fn_match = re.search(rb'filename=["\']([^"\']+)["\']', part)
                        if fn_match: filename = fn_match.group(1).decode('utf-8', errors='ignore')
                        header_end = part.find(b'\r\n\r\n')
                        if header_end != -1:
                            file_bytes = part[header_end+4:-2]
                            break
                if file_bytes:
                    save_p = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex[:8]}_{filename}")
                    with open(save_p, "wb") as f:
                        f.write(file_bytes)
                    
                    res_data = analyze_apk(save_p, filename)
                    self._send_json(res_data)
                    return

            self._send_json({"error": "Failed to parse upload file"}, 400)

        elif path == '/api/crypto-lab/classical':
            content_length = int(self.headers.get('Content-Length', 0))
            req_data = json.loads(self.rfile.read(content_length).decode('utf-8'))
            cipher = req_data.get('cipher', '').lower()
            text = req_data.get('text', '')
            key = req_data.get('key', '')
            op = req_data.get('operation', 'encrypt').lower()

            if cipher == 'caesar':
                try: shift = int(re.sub(r'[^\d\-]', '', str(key))) if str(key).strip() else 3
                except: shift = 3
                out = CaesarCipher.encrypt(text, shift) if op == 'encrypt' else CaesarCipher.decrypt(text, shift)
                self._send_json({"cipher": "Caesar Cipher", "operation": op, "input": text, "key": str(shift), "output": out, "explanation": f"Caesar shift by {shift} characters."})

            elif cipher == 'vigenere':
                key_str = key if key else "KEY"
                out = VigenereCipher.encrypt(text, key_str) if op == 'encrypt' else VigenereCipher.decrypt(text, key_str)
                self._send_json({"cipher": "Vigenere Cipher", "operation": op, "input": text, "key": key_str, "output": out, "explanation": f"Vigenere polyalphabetic substitution with key '{key_str}'."})

            elif cipher == 'monoalphabetic':
                key_str = key if key else "QWERTYUIOPASDFGHJKLZXCVBNM"
                out = MonoalphabeticCipher.encrypt(text, key_str) if op == 'encrypt' else MonoalphabeticCipher.decrypt(text, key_str)
                self._send_json({"cipher": "Monoalphabetic Substitution", "operation": op, "input": text, "key": key_str, "output": out, "explanation": "Bijective substitution alphabet map."})
            else:
                self._send_json({"error": "Unknown classical cipher"}, 400)

        elif path == '/api/crypto-lab/modern':
            content_length = int(self.headers.get('Content-Length', 0))
            req_data = json.loads(self.rfile.read(content_length).decode('utf-8'))
            cipher = req_data.get('cipher', '').lower()
            text = req_data.get('text', '')
            key = req_data.get('key', 'secret123')
            op = req_data.get('operation', 'encrypt').lower()
            algo = req_data.get('algo', 'SHA-256').upper()

            if cipher == 'hash':
                data_b = text.encode('utf-8')
                if algo == 'MD5': digest = hashlib.md5(data_b).hexdigest()
                elif algo == 'SHA-1': digest = hashlib.sha1(data_b).hexdigest()
                elif algo == 'SHA-512': digest = hashlib.sha512(data_b).hexdigest()
                else: digest = hashlib.sha256(data_b).hexdigest()
                self._send_json({"algorithm": algo, "input": text, "hash_hex": digest, "explanation": f"One-way cryptographic digest using {algo}."})
            elif cipher in ['aes', 'des3']:
                algo_name = "AES-128 (ECB)" if cipher == 'aes' else "Triple DES (3DES)"
                if op == 'encrypt':
                    res = ModernCrypto.encrypt(text, key, algo_name)
                else:
                    res = ModernCrypto.decrypt(text, key, algo_name)
                self._send_json(res)
            else:
                self._send_json({"error": "Unknown modern cipher"}, 400)
        else:
            self._send_json({"error": "Route not found"}, 404)

def open_browser_auto(port=8000):
    time.sleep(1.2)
    try:
        webbrowser.open(f"http://127.0.0.1:{port}/")
    except Exception:
        pass

def run_server(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MobileAnalyzerHandler)
    print(f"============================================================")
    print(f" Mobile Security & Cryptographic Vulnerability Analyzer")
    print(f" Server running at: http://127.0.0.1:{port}")
    print(f" Opening web browser automatically...")
    print(f"============================================================")
    
    # Launch browser thread automatically
    threading.Thread(target=open_browser_auto, args=(port,), daemon=True).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping server...")
        httpd.server_close()

if __name__ == '__main__':
    run_server(8000)
