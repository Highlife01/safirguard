"""
💎 SAFIR GUARD — Antivirüs & Anti-Spyware / Ad-Aware Güvenlik Paketi
Ana Başlatıcı Script
"""

import os
import sys
import time
import webbrowser
import threading
import uvicorn

BANNER = r"""
  ____             __ _          _____                     _ 
 / ___|  __ _     / _(_)_ __    / ____|                   | |
 \___ \ / _` |   | |_| | '__|  | |  __ _   _  __ _ _ __ __| |
  ___) | (_| |   |  _| | |     | | |_ | | | |/ _` | '__/ _` |
 |____/ \__,_|___|_| |_|_|      \_____|\__,_|\__,_|_|  \__,_|
            |_____|                                          
========================================================
 💎 SafirGuard v1.0 — Antivirus & Anti-Spyware Suite
 🛡️ AI Threat Defense & Heuristic Protection
 👨‍💻 Geliştirici: Cebrail Kara (SafirSuite)
========================================================
"""

def open_browser_delayed(url: str, delay: float = 1.5):
    def _open():
        time.sleep(delay)
        print(f"[SafirGuard] Kontrol Paneli açılıyor: {url}")
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Thread(target=_open, daemon=True).start()

def main():
    print(BANNER)
    host = "127.0.0.1"
    port = 8787
    url = f"http://{host}:{port}"

    print(f"[*] SafirGuard Web Paneli başlatılıyor...")
    print(f"[*] Erişim Adresi: {url}")
    print(f"[*] Çıkış yapmak için: CTRL + C\n")

    open_browser_delayed(url, delay=1.2)

    # Uvicorn FastAPI Sunucusunu Başlat
    uvicorn.run(
        "safir_guard.ui.server:app",
        host=host,
        port=port,
        log_level="info",
        reload=False
    )

if __name__ == "__main__":
    main()
