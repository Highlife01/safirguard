import os
import time
import threading
from typing import Dict, Any, List, Optional, Callable

from .hash_scanner import HashScanner
from .heuristic_scanner import HeuristicScanner
from .adware_spyware_engine import AdwareSpywareEngine
from .startup_inspector import StartupInspector
from ..quarantine.quarantine_vault import QuarantineVault
from ..process.process_monitor import ProcessMonitor

class ScannerCore:
    def __init__(self):
        self.hash_scanner = HashScanner()
        self.heuristic_scanner = HeuristicScanner()
        self.adware_engine = AdwareSpywareEngine()
        self.startup_inspector = StartupInspector()
        self.process_monitor = ProcessMonitor()
        self.vault = QuarantineVault()

        # Tarama Durumu
        self.state = {
            "is_scanning": False,
            "scan_type": "Idle",
            "progress": 0,
            "scanned_files": 0,
            "threats_count": 0,
            "current_file": "",
            "start_time": 0,
            "elapsed_seconds": 0,
            "threats": [],
            "logs": []
        }
        self._lock = threading.Lock()
        self._stop_requested = False

    def log(self, message: str, level: str = "INFO"):
        timestamp = time.strftime("%H:%M:%S")
        entry = {"time": timestamp, "level": level, "message": message}
        with self._lock:
            self.state["logs"].append(entry)
            if len(self.state["logs"]) > 200:
                self.state["logs"].pop(0)

    def scan_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Bir dosyayı sırasıyla İmza, Adware/LNK ve Sezgisel motorlarla kapsamlı tarar."""
        if not os.path.isfile(file_path):
            return None

        # 1. Safir SpyGuard LNK Kontrolü
        if file_path.lower().endswith(".lnk"):
            res = self.adware_engine.scan_lnk_file(file_path)
            if res:
                res["file_path"] = file_path
                return res

        # 2. İmza & Hash Taraması (EICAR & Bilinen zararlılar)
        res = self.hash_scanner.scan_file(file_path)
        if res:
            res["file_path"] = file_path
            return res

        # 3. Adware & Web Miner Desen Taraması
        res = self.adware_engine.scan_adware_text_or_script(file_path)
        if res:
            res["file_path"] = file_path
            return res

        # 4. Sezgisel (Heuristic) PE & Script Analizi
        res = self.heuristic_scanner.scan_file(file_path)
        if res:
            res["file_path"] = file_path
            return res

        return None

    def start_scan_async(self, scan_type: str = "quick", custom_path: str = "") -> bool:
        with self._lock:
            if self.state["is_scanning"]:
                return False
            self.state["is_scanning"] = True
            self.state["scan_type"] = scan_type.capitalize()
            self.state["progress"] = 0
            self.state["scanned_files"] = 0
            self.state["threats_count"] = 0
            self.state["threats"] = []
            self.state["start_time"] = time.time()
            self.state["elapsed_seconds"] = 0
            self._stop_requested = False

        thread = threading.Thread(target=self._run_scan_worker, args=(scan_type, custom_path), daemon=True)
        thread.start()
        return True

    def stop_scan(self):
        self._stop_requested = True
        self.log("Kullanıcı tarafından tarama durduruldu.", "WARNING")

    def _run_scan_worker(self, scan_type: str, custom_path: str):
        self.log(f"💎 SafirGuard {scan_type.upper()} taraması başlatıldı.", "INFO")
        targets = []

        user_profile = os.environ.get("USERPROFILE", "")
        desktop = os.path.join(user_profile, "Desktop")
        downloads = os.path.join(user_profile, "Downloads")
        temp_dir = os.environ.get("TEMP", "")
        scratch_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

        if scan_type == "quick":
            targets = [desktop, downloads, scratch_dir]
            # Hızlı taramada çalışan süreçleri de denetle
            self.log("Çalışan sistem süreçleri denetleniyor...", "INFO")
            procs = self.process_monitor.scan_running_processes()
            for p in procs:
                if p["risk_level"] in ["High", "Suspicious"]:
                    threat = {
                        "matched": True,
                        "method": "Process Inspector",
                        "threat_name": f"Proc.{p['name']}",
                        "threat_type": "Suspicious Process",
                        "severity": p["risk_level"],
                        "description": "; ".join(p["reasons"]),
                        "file_path": f"PID: {p['pid']} - {p['exe'] or p['name']}",
                        "pid": p["pid"]
                    }
                    self._add_threat(threat)

        elif scan_type == "adware":
            self.log("🔎 Safir SpyGuard Modu: Tarayıcı kısayolları, Başlangıç kayıtları ve PUP kalıntıları taranıyor...", "INFO")
            targets = [desktop, downloads, os.path.join(user_profile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu")]
            
            # Başlangıç (Autoruns) Denetimi
            autoruns = self.startup_inspector.scan_startup_entries()
            for entry in autoruns:
                if entry["risk_level"] in ["High", "Suspicious"]:
                    threat = {
                        "matched": True,
                        "method": "Startup Autoruns Inspector",
                        "threat_name": f"Autorun.{entry['name']}",
                        "threat_type": "Suspicious Startup Entry",
                        "severity": entry["risk_level"],
                        "description": f"Başlangıç Konumu: {entry['location']} - {'; '.join(entry['reasons'])}",
                        "file_path": entry["command"]
                    }
                    self._add_threat(threat)

        elif scan_type == "custom" and custom_path:
            targets = [custom_path]
        else: # Full
            targets = [desktop, downloads, temp_dir, scratch_dir]

        # Dosyaları topla
        file_list = []
        for target in targets:
            if not target or not os.path.exists(target):
                continue
            if os.path.isfile(target):
                file_list.append(target)
            else:
                for root, _, files in os.walk(target):
                    # Karantina kasasını taramaktan kaçın
                    if "quarantine_vault" in root.lower():
                        continue
                    for f in files:
                        file_list.append(os.path.join(root, f))
                        if len(file_list) >= 1500 and scan_type == "quick":
                            break

        total_files = len(file_list)
        self.log(f"Taranacak toplam dosya sayısı: {total_files}", "INFO")

        for idx, file_path in enumerate(file_list):
            if self._stop_requested:
                break

            with self._lock:
                self.state["current_file"] = os.path.basename(file_path)
                self.state["scanned_files"] = idx + 1
                self.state["progress"] = int(((idx + 1) / max(total_files, 1)) * 100)
                self.state["elapsed_seconds"] = round(time.time() - self.state["start_time"], 1)

            try:
                result = self.scan_file(file_path)
                if result:
                    self._add_threat(result)
                    self.log(f"⚠️ TEHDİT BULUNDU: {result['threat_name']} ({os.path.basename(file_path)})", "WARNING")
            except Exception:
                pass

            # Arayüzün akıcı güncellenmesi için mikro duraklama
            time.sleep(0.002)

        with self._lock:
            self.state["is_scanning"] = False
            self.state["progress"] = 100
            self.state["current_file"] = "Tarama tamamlandı."
            self.state["elapsed_seconds"] = round(time.time() - self.state["start_time"], 1)

        self.log(f"✅ Tarama başarıyla sonuçlandı. {self.state['scanned_files']} dosya incelendi, {self.state['threats_count']} tehdit tespit edildi.", "SUCCESS")

    def _add_threat(self, threat: dict):
        with self._lock:
            self.state["threats"].append(threat)
            self.state["threats_count"] = len(self.state["threats"])

    def get_state(self) -> dict:
        with self._lock:
            state_copy = dict(self.state)
            state_copy["threats"] = list(self.state["threats"])
            state_copy["logs"] = list(self.state["logs"])
            if state_copy["is_scanning"]:
                state_copy["elapsed_seconds"] = round(time.time() - state_copy["start_time"], 1)
            return state_copy
