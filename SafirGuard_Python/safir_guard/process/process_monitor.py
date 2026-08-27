import os
from typing import List, Dict, Any, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

SUSPICIOUS_NAMES = ["svch0st.exe", "miner.exe", "xmrig.exe", "taskmgr32.exe", "lsasss.exe"]

class ProcessMonitor:
    def __init__(self):
        pass

    def scan_running_processes(self) -> List[Dict[str, Any]]:
        results = []
        if not PSUTIL_AVAILABLE:
            return results

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_info']):
            try:
                info = proc.info
                pid = info.get('pid')
                name = info.get('name') or "Unknown"
                exe = info.get('exe') or ""
                cmdline = " ".join(info.get('cmdline') or [])
                mem_mb = round((info['memory_info'].rss / (1024 * 1024)), 1) if info.get('memory_info') else 0
                cpu = info.get('cpu_percent') or 0.0

                risk, reasons = self._evaluate_process(name, exe, cmdline)

                results.append({
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "cmdline": cmdline,
                    "memory_mb": mem_mb,
                    "cpu_percent": cpu,
                    "risk_level": risk,
                    "reasons": reasons
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # En yüksek risklileri ve en çok kaynak kullananları öne al
        results.sort(key=lambda x: (1 if x["risk_level"] == "High" else (2 if x["risk_level"] == "Suspicious" else 3), -x["memory_mb"]))
        return results

    def _evaluate_process(self, name: str, exe: str, cmdline: str) -> (str, List[str]):
        reasons = []
        name_lower = name.lower()
        exe_lower = exe.lower()
        cmd_lower = cmdline.lower()

        if any(s in name_lower for s in SUSPICIOUS_NAMES):
            reasons.append(f"Zararlı veya Sahte Süreç İsmi: {name}")

        if "temp" in exe_lower or "\\appdata\\local\\temp" in exe_lower:
            reasons.append("Geçici (%TEMP%) klasöründen çalışan çalıştırılabilir")

        if "downloads" in exe_lower:
            reasons.append("İndirilenler (Downloads) klasöründen doğrudan çalışan süreç")

        if "-windowstyle hidden" in cmd_lower or "-enc " in cmd_lower or "bypass" in cmd_lower:
            reasons.append("Gizli veya Yetki Aşan Komut Satırı Argümanı")

        if any(m in cmd_lower for m in ["stratum+tcp://", "xmrig", "cryptonight"]):
            reasons.append("Arka Planda Kripto Para Madenciliği (CoinMiner)")

        if reasons:
            risk = "High" if len(reasons) >= 2 or "CoinMiner" in "".join(reasons) else "Suspicious"
        else:
            risk = "Safe"

        return risk, reasons

    def kill_process(self, pid: int) -> bool:
        if not PSUTIL_AVAILABLE:
            return False
        try:
            p = psutil.Process(pid)
            p.terminate()
            p.wait(timeout=3)
            return True
        except Exception as e:
            try:
                p.kill()
                return True
            except Exception:
                return False
