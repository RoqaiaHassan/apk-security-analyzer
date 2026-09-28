import hashlib
import zipfile
import os
import shutil
from typing import Dict, Any, List

class APKParser:
    @staticmethod
    def calculate_hashes(file_path: str) -> Dict[str, str]:
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()

        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                md5.update(chunk)
                sha1.update(chunk)

        return {
            "sha256": sha256.hexdigest(),
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest()
        }

    @staticmethod
    def validate_and_extract(apk_path: str, output_dir: str) -> Dict[str, Any]:
        if not zipfile.is_zipfile(apk_path):
            raise ValueError("Invalid APK file: Not a valid ZIP archive.")

        os.makedirs(output_dir, exist_ok=True)
        extracted_files = []

        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                # Prevent path traversal vulnerabilities (Zip Slip)
                target_path = os.path.abspath(os.path.join(output_dir, member.filename))
                if not target_path.startswith(os.path.abspath(output_dir)):
                    continue
                zip_ref.extract(member, output_dir)
                extracted_files.append(member.filename)

        return {
            "is_valid": True,
            "extracted_count": len(extracted_files),
            "files": extracted_files
        }
