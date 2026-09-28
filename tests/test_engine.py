import unittest
import os
import sys

# Ensure parent directory is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.crypto.classical import CaesarCipher, VigenereCipher, MonoalphabeticCipher
from backend.crypto.score import SecurityScoreCalculator
from backend.analyzers.apk_parser import APKParser
from backend.analyzers.manifest import ManifestAnalyzer
from backend.analyzers.dex_analyzer import DexAnalyzer
from backend.analyzers.crypto_engine import CryptoEngine
from backend.analyzers.secrets_engine import SecretsEngine

class TestEngine(unittest.TestCase):
    def test_classical_ciphers(self):
        enc = CaesarCipher.encrypt("HELLO", 3)
        self.assertEqual(enc, "KHOOR")
        dec = CaesarCipher.decrypt("KHOOR", 3)
        self.assertEqual(dec, "HELLO")

        vig_enc = VigenereCipher.encrypt("ATTACKATDAWN", "LEMON")
        self.assertEqual(vig_enc, "LXFOPVEFRNHR")

    def test_sample_apk_scanning(self):
        apk_path = os.path.join(os.path.dirname(__file__), "sample_apks", "TestApp_AES_ECB.apk")
        if not os.path.exists(apk_path):
            self.skipTest("Sample APK not generated")

        hashes = APKParser.calculate_hashes(apk_path)
        self.assertTrue(len(hashes["sha256"]) == 64)

        extract_dir = os.path.join(os.path.dirname(__file__), "temp_test_extract")
        res = APKParser.validate_and_extract(apk_path, extract_dir)
        self.assertTrue(res["is_valid"])


        manifest = ManifestAnalyzer.parse_manifest(extract_dir)
        self.assertEqual(manifest["package_name"], "com.crypto.aecb")

        strings = DexAnalyzer.extract_strings(extract_dir)
        crypto_findings = CryptoEngine.analyze_crypto_usage(strings)
        secret_findings = SecretsEngine.analyze_secrets(strings)

        # Ensure AES/ECB was detected
        detected_rules = [f["rule_id"] for f in crypto_findings + secret_findings]
        self.assertIn("RULE-002", detected_rules) # AES ECB

        # Cleanup
        import shutil
        shutil.rmtree(extract_dir, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
