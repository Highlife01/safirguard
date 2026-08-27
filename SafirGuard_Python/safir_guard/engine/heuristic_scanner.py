import os
import math
import re
from typing import Optional, Dict, Any, List

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

SUSPICIOUS_APIS = {
    "VirtualAllocEx": "Process Memory Allocation (Memory Injection)",
    "WriteProcessMemory": "Process Memory Modification (Code Injection)",
    "CreateRemoteThread": "Remote Thread Execution (Process Injection)",
    "SetWindowsHookExA": "System Hooking (Keylogging/Input Capture)",
    "SetWindowsHookExW": "System Hooking (Keylogging/Input Capture)",
    "NtUnmapViewOfSection": "Process Hollowing Technique",
    "QueueUserAPC": "Early Bird Injection / APC Queueing",
    "IsDebuggerPresent": "Anti-Analysis / Anti-Debugging Check",
    "URLDownloadToFileA": "Silent Dropper / Downloader",
    "URLDownloadToFileW": "Silent Dropper / Downloader"
}

PACKER_SECTIONS = ["upx0", "upx1", "upx2", ".vmp0", ".vmp1", ".themida", ".aspack", ".fsg", ".petite"]

class HeuristicScanner:
    def __init__(self):
        pass

    def calculate_entropy(self, data: bytes) -> float:
        """Shannon Entropisi hesaplar (0.0 - 8.0 arası). 7.2 üzeri yüksek oranda şifrelenmiş veya paketlenmiştir."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    def scan_pe_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Windows Portable Executable (.exe, .dll) dosyalarını sezgisel olarak inceler."""
        if not PEFILE_AVAILABLE:
            return None

        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories()
            
            reasons = []
            score = 0
            detected_apis = []

            # 1. Bölüm (Section) İncelemesi ve Entropi
            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00').lower()
                sec_data = section.get_data()
                entropy = self.calculate_entropy(sec_data)

                # Bilinen paketleyici bölüm isimleri
                if any(p in sec_name for p in PACKER_SECTIONS):
                    reasons.append(f"Paketlenmiş PE Bölümü Tespit Edildi: '{sec_name}'")
                    score += 35

                # Yüksek entropili çalıştırılabilir bölüm (Packed / Crypt)
                if entropy > 7.3 and (section.Characteristics & 0x20000000): # IMAGE_SCN_MEM_EXECUTE
                    reasons.append(f"Yüksek Entropili Çalıştırılabilir Bölüm ({sec_name}: {entropy}/8.0 - Olası Obfuscation/Packer)")
                    score += 40

            # 2. Şüpheli API Import İncelemesi
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            if func_name in SUSPICIOUS_APIS:
                                detected_apis.append(f"{func_name} ({SUSPICIOUS_APIS[func_name]})")
                                score += 20

            if len(detected_apis) >= 2:
                reasons.append(f"Şüpheli API Kombinasyonu: {', '.join(detected_apis[:3])}")

            pe.close()

            if score >= 45:
                severity = "Critical" if score >= 70 else ("High" if score >= 50 else "Medium")
                return {
                    "matched": True,
                    "method": "Heuristic PE Analysis",
                    "threat_name": "Heur.Suspicious.PackedBinary" if score >= 60 else "Heur.Suspicious.Binary",
                    "threat_type": "Suspicious Executable",
                    "severity": severity,
                    "description": f"Sezgisel PE Analizi: {'; '.join(reasons)}",
                    "score": score,
                    "reasons": reasons
                }

        except Exception:
            pass

        return None

    def scan_script_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """PowerShell, VBScript, Batch ve Shell scriptlerindeki şüpheli teknikleri inceler."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in [".ps1", ".vbs", ".bat", ".cmd", ".js", ".hta", ".wsf"]:
            return None

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            suspicious_indicators = [
                (r"powershell.*(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "Base64 Şifrelenmiş PowerShell Komutu", 40),
                (r"downloadstring|downloaddata|downloadfile", "İzinsiz Ağ Üzerinden Dosya İndirme Komutu", 30),
                (r"wscript\.shell.*run.*(cmd|powershell).*hidden", "Arka Planda Gizli Shell Çalıştırma", 35),
                (r"Invoke-ReflectivePEInjection", "Reflective DLL/PE Bellek Enjeksiyonu", 50),
                (r"vssadmin.*delete.*shadows", "Ransomware Gölge Kopya Silme Komutu", 60)
            ]

            total_score = 0
            findings = []

            for pattern, desc, pts in suspicious_indicators:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append(desc)
                    total_score += pts

            if total_score >= 35:
                severity = "Critical" if total_score >= 60 else "High"
                return {
                    "matched": True,
                    "method": "Heuristic Script Analysis",
                    "threat_name": "Heur.Malicious.ScriptPayload",
                    "threat_type": "Malicious Script",
                    "severity": severity,
                    "description": f"Zararlı Script Kalıpları: {', '.join(findings)}",
                    "score": total_score,
                    "reasons": findings
                }
        except Exception:
            pass

        return None

    def scan_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        if not os.path.isfile(file_path):
            return None

        ext = os.path.splitext(file_path)[1].lower()
        if ext in [".exe", ".dll", ".sys", ".scr", ".cpl"]:
            return self.scan_pe_file(file_path)
        elif ext in [".ps1", ".vbs", ".bat", ".cmd", ".js", ".hta"]:
            return self.scan_script_file(file_path)

        return None
