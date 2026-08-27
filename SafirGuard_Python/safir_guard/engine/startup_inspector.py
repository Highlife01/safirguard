import os
import sys
from typing import List, Dict, Any

try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False

REG_RUN_LOCATIONS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
] if WINREG_AVAILABLE else []

class StartupInspector:
    def __init__(self):
        pass

    def get_startup_folder_paths(self) -> List[Dict[str, str]]:
        paths = []
        user_startup = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        common_startup = os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")

        if os.path.exists(user_startup):
            paths.append({"type": "User Startup Folder", "path": user_startup})
        if os.path.exists(common_startup):
            paths.append({"type": "Common Startup Folder", "path": common_startup})

        return paths

    def scan_startup_entries(self) -> List[Dict[str, Any]]:
        entries = []

        # 1. Registry Run Keys
        if WINREG_AVAILABLE:
            for root_key, sub_key, loc_name in REG_RUN_LOCATIONS:
                try:
                    with winreg.OpenKey(root_key, sub_key, 0, winreg.KEY_READ) as key:
                        count = winreg.QueryInfoKey(key)[1]
                        for i in range(count):
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                risk, reasons = self._evaluate_entry(name, str(value))
                                entries.append({
                                    "name": name,
                                    "command": str(value),
                                    "location": loc_name,
                                    "source_type": "Registry",
                                    "risk_level": risk,
                                    "reasons": reasons,
                                    "can_disable": True
                                })
                            except Exception:
                                continue
                except Exception:
                    continue

        # 2. Startup Klasörleri
        for folder_info in self.get_startup_folder_paths():
            folder_path = folder_info["path"]
            loc_name = folder_info["type"]
            try:
                for file_name in os.listdir(folder_path):
                    full_path = os.path.join(folder_path, file_name)
                    if os.path.isfile(full_path) and not file_name.lower() == "desktop.ini":
                        risk, reasons = self._evaluate_entry(file_name, full_path)
                        entries.append({
                            "name": file_name,
                            "command": full_path,
                            "location": loc_name,
                            "source_type": "Startup Folder",
                            "risk_level": risk,
                            "reasons": reasons,
                            "can_disable": True
                        })
            except Exception:
                continue

        return entries

    def _evaluate_entry(self, name: str, command: str) -> (str, List[str]):
        reasons = []
        cmd_lower = command.lower()
        name_lower = name.lower()

        # Risk faktörleri
        if "temp" in cmd_lower or "\\appdata\\local\\temp" in cmd_lower:
            reasons.append("Geçici (%TEMP%) dizininden çalışıyor (Yüksek Tehdit İndikatörü)")

        if any(ext in cmd_lower for ext in [".vbs", ".bat", ".cmd", ".ps1", ".hta"]):
            reasons.append("Başlangıçta doğrudan script çalıştırılıyor")

        if "powershell" in cmd_lower and any(f in cmd_lower for f in ["-enc", "-hidden", "bypass"]):
            reasons.append("Gizli/Şifrelenmiş PowerShell başlatma argümanı")

        if any(fake in name_lower for fake in ["svch0st", "system32_", "updater_bg"]):
            reasons.append("Sistem ismi taklit eden şüpheli servis/uygulama adı")

        if reasons:
            risk = "High" if len(reasons) >= 2 or "temp" in cmd_lower else "Suspicious"
        else:
            risk = "Safe"

        return risk, reasons
