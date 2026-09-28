import re
from typing import List, Dict, Any, Tuple

class NetworkEngine:
    @staticmethod
    def analyze_network(string_records: List[Tuple[str, str, int]]) -> List[Dict[str, Any]]:
        findings = []
        seen = set()

        # Match http:// URLs ignoring standard Android schema namespaces
        http_regex = r'http://(?!schemas\.android\.com|www\.w3\.org|ns\.adobe\.com)[a-zA-Z0-9\.\-_/]+'

        for file_path, line_content, line_num in string_records:
            match = re.search(http_regex, line_content, re.IGNORECASE)
            if match:
                url = match.group(0)
                key = ("RULE-013", file_path, line_num)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "rule_id": "RULE-013",
                        "vulnerability": "Cleartext HTTP Communication",
                        "severity": "Medium",
                        "category": "Network Security",
                        "algorithm": "HTTP",
                        "file": file_path,
                        "line": line_num,
                        "evidence": line_content[:120],
                        "description": f"Unencrypted HTTP connection endpoint discovered: {url}",
                        "status": "DETECTED"
                    })

            # Check TrustAllManager / SSL Bypass
            if "TrustAllManager" in line_content or "ALLOW_ALL_HOSTNAME_VERIFIER" in line_content or "checkClientTrusted" in line_content:
                key = ("RULE-018", file_path, line_num)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "rule_id": "RULE-018",
                        "vulnerability": "Trust All Certificates / SSL Bypass",
                        "severity": "Critical",
                        "category": "Network Security",
                        "algorithm": "SSL/TLS",
                        "file": file_path,
                        "line": line_num,
                        "evidence": line_content[:120],
                        "description": "Found custom SSL TrustManager or HostnameVerifier ignoring certificate validation.",
                        "status": "DETECTED"
                    })

        return findings
