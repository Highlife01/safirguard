import os
import json
import time
import shutil
import hashlib
from typing import List, Dict, Optional

VAULT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "quarantine_vault"))
META_FILE = os.path.join(VAULT_DIR, "quarantine_manifest.json")
XOR_KEY = 0x5A  # Güvenli izolasyon için byte bazlı XOR maskeleme

class QuarantineVault:
    def __init__(self, vault_dir: str = VAULT_DIR):
        self.vault_dir = vault_dir
        self.meta_file = os.path.join(self.vault_dir, "quarantine_manifest.json")
        self._ensure_vault()

    def _ensure_vault(self):
        if not os.path.exists(self.vault_dir):
            os.makedirs(self.vault_dir, exist_ok=True)
        if not os.path.exists(self.meta_file):
            self._save_manifest({})

    def _load_manifest(self) -> Dict[str, dict]:
        try:
            if os.path.exists(self.meta_file):
                with open(self.meta_file, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_manifest(self, manifest: Dict[str, dict]):
        with open(self.meta_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)

    def _xor_transform(self, data: bytes) -> bytes:
        return bytes([b ^ XOR_KEY for b in data])

    def quarantine_file(self, file_path: str, threat_name: str, threat_type: str = "Malware") -> Optional[dict]:
        if not os.path.isfile(file_path):
            return None

        try:
            with open(file_path, "rb") as f:
                content = f.read()

            sha256 = hashlib.sha256(content).hexdigest()
            file_size = len(content)
            file_name = os.path.basename(file_path)
            q_id = f"Q_{int(time.time())}_{sha256[:8]}"
            vault_filename = f"{q_id}.safir_locked"
            vault_path = os.path.join(self.vault_dir, vault_filename)

            # Dosyayı XOR ile kilitle ve kasaya yaz
            locked_content = self._xor_transform(content)
            with open(vault_path, "wb") as f:
                f.write(locked_content)

            # Orijinal dosyayı güvenle sil
            try:
                os.remove(file_path)
            except Exception as e:
                # Eğer dosya kullanımda ise sıfırla
                pass

            manifest = self._load_manifest()
            entry = {
                "id": q_id,
                "file_name": file_name,
                "original_path": os.path.abspath(file_path),
                "threat_name": threat_name,
                "threat_type": threat_type,
                "file_size": file_size,
                "sha256": sha256,
                "vault_file": vault_filename,
                "quarantine_time": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            manifest[q_id] = entry
            self._save_manifest(manifest)
            return entry

        except Exception as e:
            print(f"[Quarantine Error] {file_path} karantinaya alınamadı: {e}")
            return None

    def restore_file(self, q_id: str) -> bool:
        manifest = self._load_manifest()
        if q_id not in manifest:
            return False

        entry = manifest[q_id]
        vault_path = os.path.join(self.vault_dir, entry["vault_file"])
        orig_path = entry["original_path"]

        if not os.path.exists(vault_path):
            return False

        try:
            with open(vault_path, "rb") as f:
                locked_content = f.read()

            orig_content = self._xor_transform(locked_content)

            orig_dir = os.path.dirname(orig_path)
            if not os.path.exists(orig_dir):
                os.makedirs(orig_dir, exist_ok=True)

            with open(orig_path, "wb") as f:
                f.write(orig_content)

            # Kasadaki kilitli dosyayı ve kaydı temizle
            os.remove(vault_path)
            del manifest[q_id]
            self._save_manifest(manifest)
            return True
        except Exception as e:
            print(f"[Restore Error] {q_id} geri yüklenemedi: {e}")
            return False

    def delete_permanently(self, q_id: str) -> bool:
        manifest = self._load_manifest()
        if q_id not in manifest:
            return False

        entry = manifest[q_id]
        vault_path = os.path.join(self.vault_dir, entry["vault_file"])

        if os.path.exists(vault_path):
            try:
                # Güvenli shred (üzerine yazıp silme)
                size = os.path.getsize(vault_path)
                with open(vault_path, "wb") as f:
                    f.write(b"\x00" * size)
                os.remove(vault_path)
            except Exception:
                pass

        del manifest[q_id]
        self._save_manifest(manifest)
        return True

    def list_quarantined(self) -> List[dict]:
        manifest = self._load_manifest()
        return list(manifest.values())
