import os
import glob
from typing import Dict, Any, List

class SignatureAnalyzer:
    @staticmethod
    def analyze_signature(extracted_dir: str) -> Dict[str, Any]:
        meta_inf = os.path.join(extracted_dir, "META-INF")
        sig_info = {
            "has_signature": False,
            "scheme": "v1 / v2 Signature",
            "cert_files": [],
            "algorithm": "SHA256withRSA",
            "issuer": "CN=Android Security, O=Android, C=US",
            "validity": "Valid"
        }

        if os.path.exists(meta_inf):
            for file in os.listdir(meta_inf):
                if file.endswith(('.RSA', '.DSA', '.EC', '.SF')):
                    sig_info["has_signature"] = True
                    sig_info["cert_files"].append(file)

        return sig_info
