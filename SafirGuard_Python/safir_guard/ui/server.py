import os
import time
from typing import Optional
from pydantic import BaseModel
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..engine.scanner_core import ScannerCore
from ..monitor.realtime_shield import RealtimeShield

BASE_DIR = os.path.dirname(__file__)
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

app = FastAPI(title="SafirGuard Antivirus & Anti-Spyware Suite", version="1.0.0")

# Statik ve şablon dizinlerini bağla
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Çekirdek motorlar
scanner = ScannerCore()
shield = RealtimeShield(on_threat_detected=lambda t: scanner.log(f"🛡️ Canlı Kalkan Tehdit Yakaladı: {t['threat_name']}", "WARNING"))

# Varsayılan olarak canlı kalkanı başlat
shield.start_shield(scan_callback=scanner.scan_file)

class ScanRequest(BaseModel):
    type: str = "quick" # quick, full, adware, custom
    custom_path: Optional[str] = ""

class QuarantineActionRequest(BaseModel):
    action: str # quarantine, restore, delete
    id: Optional[str] = None
    file_path: Optional[str] = None
    threat_name: Optional[str] = "Manual Threat"
    threat_type: Optional[str] = "Suspicious"

class ProcessKillRequest(BaseModel):
    pid: int

class ShieldToggleRequest(BaseModel):
    enable: bool

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/status")
async def get_system_status():
    scan_state = scanner.get_state()
    shield_status = shield.get_status()
    quarantined_items = scanner.vault.list_quarantined()

    return {
        "status": "online",
        "scanner": scan_state,
        "shield": shield_status,
        "quarantine_count": len(quarantined_items),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

@app.post("/api/scan/start")
async def start_scan(payload: ScanRequest):
    success = scanner.start_scan_async(scan_type=payload.type, custom_path=payload.custom_path or "")
    if not success:
        return JSONResponse({"status": "error", "message": "Zaten devam eden bir tarama mevcut."}, status_code=400)
    return {"status": "success", "message": f"{payload.type.capitalize()} taraması başlatıldı."}

@app.post("/api/scan/stop")
async def stop_scan():
    scanner.stop_scan()
    return {"status": "success", "message": "Tarama durdurma sinyali gönderildi."}

@app.get("/api/quarantine/list")
async def list_quarantine():
    items = scanner.vault.list_quarantined()
    return {"items": items}

@app.post("/api/quarantine/action")
async def handle_quarantine(payload: QuarantineActionRequest):
    if payload.action == "quarantine":
        if not payload.file_path:
            raise HTTPException(status_code=400, detail="Dosya yolu gereklidir.")
        entry = scanner.vault.quarantine_file(payload.file_path, payload.threat_name or "Detected Threat", payload.threat_type or "Malware")
        if entry:
            scanner.log(f"🔒 Dosya karantinaya alındı: {payload.file_path}", "SUCCESS")
            return {"status": "success", "entry": entry}
        raise HTTPException(status_code=500, detail="Dosya karantinaya alınamadı.")

    elif payload.action == "restore":
        if not payload.id:
            raise HTTPException(status_code=400, detail="Karantina ID gereklidir.")
        ok = scanner.vault.restore_file(payload.id)
        if ok:
            scanner.log(f"🔓 Dosya karantinadan geri yüklendi (ID: {payload.id})", "INFO")
            return {"status": "success"}
        raise HTTPException(status_code=500, detail="Geri yükleme başarısız.")

    elif payload.action == "delete":
        if not payload.id:
            raise HTTPException(status_code=400, detail="Karantina ID gereklidir.")
        ok = scanner.vault.delete_permanently(payload.id)
        if ok:
            scanner.log(f"🗑️ Karantinadaki dosya kalıcı olarak imha edildi (ID: {payload.id})", "WARNING")
            return {"status": "success"}
        raise HTTPException(status_code=500, detail="Silme işlemi başarısız.")

    raise HTTPException(status_code=400, detail="Geçersiz işlem.")

@app.get("/api/autoruns")
async def get_autoruns():
    entries = scanner.startup_inspector.scan_startup_entries()
    return {"entries": entries}

@app.get("/api/processes")
async def get_processes():
    procs = scanner.process_monitor.scan_running_processes()
    return {"processes": procs}

@app.post("/api/process/kill")
async def kill_process(payload: ProcessKillRequest):
    ok = scanner.process_monitor.kill_process(payload.pid)
    if ok:
        scanner.log(f"🛑 Süreç sonlandırıldı (PID: {payload.pid})", "WARNING")
        return {"status": "success", "message": f"PID {payload.pid} başarıyla sonlandırıldı."}
    return JSONResponse({"status": "error", "message": "Süreç sonlandırılamadı veya erişim engellendi."}, status_code=500)

@app.post("/api/shield/toggle")
async def toggle_shield(payload: ShieldToggleRequest):
    if payload.enable:
        shield.start_shield(scan_callback=scanner.scan_file)
        scanner.log("🛡️ Gerçek Zamanlı Koruma Kalkanı ETKİNLEŞTİRİLDİ.", "SUCCESS")
    else:
        shield.stop_shield()
        scanner.log("⚠️ Gerçek Zamanlı Koruma Kalkanı DEVRE DIŞI BIRAKILDI.", "WARNING")
    return {"status": "success", "is_active": shield.is_active}
