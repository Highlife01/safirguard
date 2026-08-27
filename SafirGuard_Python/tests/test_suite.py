import os
import sys
import tempfile
import unittest

# Modül yolunu ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from safir_guard.engine.scanner_core import ScannerCore
from safir_guard.engine.hash_scanner import HashScanner
from safir_guard.engine.heuristic_scanner import HeuristicScanner
from safir_guard.engine.adware_spyware_engine import AdwareSpywareEngine
from safir_guard.engine.startup_inspector import StartupInspector
from safir_guard.quarantine.quarantine_vault import QuarantineVault

class TestSafirGuardSuite(unittest.TestCase):
    def setUp(self):
        self.scanner = ScannerCore()
        self.vault = self.scanner.vault
        self.temp_dir = tempfile.mkdtemp(prefix="safir_test_")

    def test_01_signature_detection(self):
        """SafirGuard standart zararsız test imzasının tespit edildiğini doğrular."""
        test_string = "### SAFIR-ANTIVIRUS-STANDARD-TEST-SAMPLE ###"
        sample_path = os.path.join(self.temp_dir, "safir_test_sig.txt")
        with open(sample_path, "w", encoding="utf-8") as f:
            f.write(test_string)

        result = self.scanner.scan_file(sample_path)
        self.assertIsNotNone(result, "Test imzası tespit edilmeliydi.")
        self.assertEqual(result["threat_name"], "Safir.Standard.Test.Signature")
        print(f"\n[Test Başarılı] Test İmzası Tespit Edildi: {result['threat_name']}")

    def test_02_adware_pattern_detection(self):
        """Ad-Aware tarzı reklam enjektörü ve domain tespitini doğrular."""
        adware_content = "function inject() { window.location = 'http://sweet-page.com/search?q=tracking'; }"
        sample_path = os.path.join(self.temp_dir, "ad_inject.js")
        with open(sample_path, "w", encoding="utf-8") as f:
            f.write(adware_content)

        result = self.scanner.scan_file(sample_path)
        self.assertIsNotNone(result, "Adware scripti tespit edilmeliydi.")
        self.assertEqual(result["threat_type"], "Adware / Spyware")
        print(f"[Test Başarılı] Adware Tespit Edildi: {result['threat_name']}")

    def test_03_heuristic_script_detection(self):
        """Zararlı PowerShell komut zincirinin sezgisel tespitini doğrular."""
        ps_content = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="
        sample_path = os.path.join(self.temp_dir, "malicious_runner.ps1")
        with open(sample_path, "w", encoding="utf-8") as f:
            f.write(ps_content)

        result = self.scanner.scan_file(sample_path)
        self.assertIsNotNone(result, "Şüpheli script tespit edilmeliydi.")
        self.assertEqual(result["threat_type"], "Malicious Script")
        print(f"[Test Başarılı] Sezgisel Script Tespit Edildi: {result['threat_name']}")

    def test_04_quarantine_and_restore(self):
        """Karantina kasasına alma ve geri yükleme döngüsünü doğrular."""
        test_file = os.path.join(self.temp_dir, "danger_sample.exe")
        original_bytes = b"MALICIOUS_DUMMY_BYTECODE_SAMPLE_FOR_TESTING_PURPOSES"
        with open(test_file, "wb") as f:
            f.write(original_bytes)

        # 1. Karantinaya al
        entry = self.vault.quarantine_file(test_file, "Test.Threat.Dummy", "Test")
        self.assertIsNotNone(entry)
        self.assertFalse(os.path.exists(test_file), "Orijinal dosya silinip izole edilmiş olmalı.")

        q_id = entry["id"]
        # 2. Geri yükle
        ok = self.vault.restore_file(q_id)
        self.assertTrue(ok)
        self.assertTrue(os.path.exists(test_file), "Dosya orijinal konumuna geri yüklenmiş olmalı.")

        with open(test_file, "rb") as f:
            restored_bytes = f.read()
        self.assertEqual(original_bytes, restored_bytes, "Geri yüklenen baytlar orijinaliyle birebir aynı olmalı.")
        print(f"[Test Başarılı] Karantina İzolasyon ve Geri Yükleme Doğrulandı.")

    def test_05_startup_inspector(self):
        """Başlangıç denetçisinin hata vermeden çalıştığını doğrular."""
        inspector = StartupInspector()
        entries = inspector.scan_startup_entries()
        self.assertIsInstance(entries, list)
        print(f"[Test Başarılı] Başlangıç Denetimi Yapıldı ({len(entries)} girdi bulundu).")

if __name__ == "__main__":
    unittest.main()
