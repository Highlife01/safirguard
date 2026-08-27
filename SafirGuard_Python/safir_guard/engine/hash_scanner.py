import os
import json
import hashlib
from typing import Optional, Dict, Any

DB_PATH = os.path.join(os.path.dirname(__file__), "signature_db.json")

class HashScanner:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.signatures = []
        self.content_patterns = []
        self._load_signatures()

    def _load_signatures(self):
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.signatures = data.get("signatures", [])
                    self.content_patterns = data.get("content_patterns", [])
        except Exception as e:
            print(f"[HashScanner] İmza veritabanı yüklenemedi: {e}")

    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
            return {
                "md5": md5_hash.hexdigest(),
                "sha256": sha256_hash.hexdigest()
            }
        except Exception:
            return {"md5": "", "sha256": ""}

    def scan_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        if not os.path.isfile(file_path):
            return None

        hashes = self.calculate_hashes(file_path)
        sha256 = hashes["sha256"]
        md5 = hashes["md5"]

        # 1. Tam Hash Eşleştirmesi
        for sig in self.signatures:
            if (sig.get("sha256") and sig["sha256"].lower() == sha256.lower()) or \
               (sig.get("md5") and sig["md5"].lower() == md5.lower()):
                return {
                    "matched": True,
                    "method": "Signature/Hash Match",
                    "threat_name": sig["name"],
                    "threat_type": sig["type"],
                    "severity": sig["severity"],
                    "description": sig["description"],
                    "hashes": hashes
                }

        # 2. İçerik ve Desen Eşleştirmesi (Küçük/orta boyutlu dosyalar için)
        try:
            file_size = os.path.getsize(file_path)
            if file_size < 10 * 1024 * 1024:  # 10MB altı dosyalar için hızlı içerik taraması
                with open(file_path, "rb") as f:
                    content_bytes = f.read()

                for pat in self.content_patterns:
                    pattern_bytes = pat["pattern"].encode("utf-8")
                    if pattern_bytes in content_bytes:
                        return {
                            "matched": True,
                            "method": "Pattern Match",
                            "threat_name": pat["name"],
                            "threat_type": pat["type"],
                            "severity": pat["severity"],
                            "description": pat["description"],
                            "hashes": hashes
                        }
        except Exception:
            pass

        return None
