import os
import re
import json
from typing import Optional, Dict, Any, List

DB_PATH = os.path.join(os.path.dirname(__file__), "signature_db.json")

class AdwareSpywareEngine:
    def __init__(self, db_path: str = DB_PATH):
        self.adware_domains = []
        self._load_db(db_path)

    def _load_db(self, db_path: str):
        try:
            if os.path.exists(db_path):
                with open(db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.adware_domains = data.get("adware_domains", [])
        except Exception:
            self.adware_domains = ["sweet-page.com", "search-protect.com", "babylon-toolbar.com", "search.myway.com"]

    def scan_lnk_file(self, lnk_path: str) -> Optional[Dict[str, Any]]:
        """Windows .lnk kısayollarını inceleyerek Browser Hijacker URL veya gizli komut eklemelerini tespit eder."""
        if not lnk_path.lower().endswith(".lnk") or not os.path.isfile(lnk_path):
            return None

        try:
            with open(lnk_path, "rb") as f:
                raw_bytes = f.read()

            # LNK dosyası içindeki metin dizelerini ayıkla
            strings = re.findall(rb"[\x20-\x7E]{4,}", raw_bytes)
            decoded_strings = [s.decode("latin1") for s in strings]
            full_text = " ".join(decoded_strings).lower()

            reasons = []
            for domain in self.adware_domains:
                if domain.lower() in full_text:
                    reasons.append(f"Kısayolda Bilinen Adware/Hijacker Alan Adı Bulundu: '{domain}'")

            if ("http://" in full_text or "https://" in full_text) and any(b in full_text for b in ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"]):
                # Tarayıcı kısayolunun ardına URL eklenmiş
                match = re.search(r"https?://[^\s\"']+", full_text)
                if match:
                    url = match.group(0)
                    reasons.append(f"Tarayıcı Kısayolu Yönlendirmesi (Browser Hijacker Argument): {url}")

            if "cmd.exe" in full_text or "powershell.exe" in full_text or "wscript.exe" in full_text:
                if any(k in full_text for k in ["-windowstyle hidden", "-enc", "/c start", "http"]):
                    reasons.append("Kısayolda Gizli Komut veya İndirme Zinciri (LNK Dropper)")

            if reasons:
                return {
                    "matched": True,
                    "method": "Safir SpyGuard LNK Hijacker Engine",
                    "threat_name": "Safir.SpyGuard.BrowserHijacker.LNK",
                    "threat_type": "Adware / Browser Hijacker",
                    "severity": "Medium",
                    "description": f"Zararlı Kısayol Parametresi: {'; '.join(reasons)}",
                    "reasons": reasons
                }
        except Exception:
            pass

        return None

    def scan_adware_text_or_script(self, file_path: str) -> Optional[Dict[str, Any]]:
        """HTML, JS, JSON ve konfigürasyon dosyalarında reklam enjektörleri ve casus kodları tarar."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in [".js", ".html", ".htm", ".json", ".txt", ".cfg", ".ini"]:
            return None

        try:
            if os.path.getsize(file_path) > 5 * 1024 * 1024:
                return None

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().lower()

            findings = []
            for domain in self.adware_domains:
                if domain in content:
                    findings.append(f"Adware Alan Adı İletişimi: {domain}")

            # Crypto Miner Script imzaları (CoinHive vb.)
            miner_indicators = ["coinhive.min.js", "cryptoloot.pro", "webminepool", "crypto-loot.com", "coin-have.com"]
            for m in miner_indicators:
                if m in content:
                    findings.append(f"Tarayıcı Tabanlı Web Kripto Madencisi: {m}")

            # Spyware keylogger kalıpları
            if "addeventlistener('keypress'" in content or "addeventlistener('keydown'" in content:
                if "xmlhttprequest" in content or "fetch(" in content:
                    if any(t in content for t in ["password", "creditcard", "cvv", "keylog"]):
                        findings.append("Form & Klavye Verisi Toplayan Casus Kod (Spyware Form-Grabber)")

            if findings:
                return {
                    "matched": True,
                    "method": "Safir SpyGuard Pattern & Spyware Engine",
                    "threat_name": "Safir.SpyGuard.TrackingOrInjector",
                    "threat_type": "Adware / Spyware",
                    "severity": "Medium",
                    "description": f"SpyGuard Bulgusu: {'; '.join(findings)}",
                    "reasons": findings
                }
        except Exception:
            pass

        return None

    def audit_hosts_file(self) -> List[Dict[str, Any]]:
        """Windows Hosts dosyasını inceler ve şüpheli yönlendirmeleri listeler."""
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        results = []
        if not os.path.exists(hosts_path):
            return results

        try:
            with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip, domain = parts[0], parts[1].lower()
                    # Güvenlik ve arama motorları yönlendirilmiş mi?
                    if any(s in domain for s in ["microsoft", "google", "kaspersky", "symantec", "virustotal"]):
                        if ip != "127.0.0.1" and ip != "::1" and not ip.startswith("0.0.0.0"):
                            results.append({
                                "ip": ip,
                                "domain": domain,
                                "reason": "Güvenlik veya arama motoru IP yönlendirmesi (DNS Hijack Şüphesi)"
                            })
        except Exception:
            pass

        return results
