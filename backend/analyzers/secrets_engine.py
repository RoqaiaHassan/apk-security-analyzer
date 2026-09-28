import re
from typing import List, Dict, Any, Tuple

class SecretsEngine:
    @staticmethod
    def _mask_secret(val: str) -> str:
        if len(val) <= 6:
            return "******"
        return val[:3] + "************" + val[-2:]

    @staticmethod
    def analyze_secrets(string_records: List[Tuple[str, str, int]]) -> List[Dict[str, Any]]:
        findings = []

        secret_patterns = [
            # Hardcoded Encryption Key
            (
                r'(SecretKeySpec|aes_key|encryption_key|SECRET_KEY)\s*=\s*["\']([^"\']{8,})["\']',
                "RULE-001",
                "Hardcoded Encryption Key",
                "Critical",
                "Hardcoded AES/RSA secret key variable found in bytecode."
            ),
            # Hardcoded Password
            (
                r'(password|passwd|pwd|admin_pass)\s*=\s*["\']([^"\']{4,})["\']',
                "RULE-009",
                "Hardcoded Password",
                "Critical",
                "Hardcoded user/admin password string found."
            ),
            # Google API Key
            (
                r'AIzaSy[A-Za-z0-9_-]{35}',
                "RULE-010",
                "Hardcoded Google API Key",
                "High",
                "Google API Key string detected in application code."
            ),
            # AWS Access Key
            (
                r'AKIA[0-9A-Z]{16}',
                "RULE-010",
                "Hardcoded AWS Access Key",
                "High",
                "Amazon AWS Access Key ID detected."
            ),
            # Generic Bearer Token / JWT
            (
                r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
                "RULE-010",
                "Hardcoded JWT Access Token",
                "High",
                "Hardcoded JSON Web Token (JWT) string detected."
            )
        ]

        seen = set()

        for file_path, line_content, line_num in string_records:
            for regex, rule_id, title, severity, desc in secret_patterns:
                match = re.search(regex, line_content, re.IGNORECASE)
                if match:
                    key = (rule_id, file_path, line_num)
                    if key not in seen:
                        seen.add(key)
                        secret_val = match.group(0)
                        masked_evidence = line_content.replace(secret_val, SecretsEngine._mask_secret(secret_val))[:120]
                        findings.append({
                            "rule_id": rule_id,
                            "vulnerability": title,
                            "severity": severity,
                            "category": "Secrets Exposure",
                            "algorithm": "N/A",
                            "file": file_path,
                            "line": line_num,
                            "evidence": masked_evidence,
                            "description": desc,
                            "status": "DETECTED"
                        })

        return findings
