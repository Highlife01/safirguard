import os
import time
import threading
from typing import List, Callable, Optional

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

class ShieldHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    def __init__(self, on_file_created: Callable[[str], None]):
        self.on_file_created = on_file_created
        self.last_scanned = {}

    def on_created(self, event):
        if event.is_directory:
            return
        self._process_path(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._process_path(event.src_path)

    def _process_path(self, path: str):
        now = time.time()
        # Çok sık tetiklemeyi önlemek için 1 saniye throttle
        if path in self.last_scanned and (now - self.last_scanned[path]) < 1.5:
            return
        self.last_scanned[path] = now
        time.sleep(0.1) # Dosyanın yazılmasının bitmesini bekle
        if os.path.exists(path) and os.path.isfile(path):
            self.on_file_created(path)

class RealtimeShield:
    def __init__(self, on_threat_detected: Optional[Callable[[dict], None]] = None):
        self.on_threat_detected = on_threat_detected
        self.observer = None
        self.is_active = False
        self.monitored_paths = []
        self._lock = threading.Lock()

    def get_default_watch_dirs(self) -> List[str]:
        user_profile = os.environ.get("USERPROFILE", "")
        paths = [
            os.path.join(user_profile, "Downloads"),
            os.path.join(user_profile, "Desktop")
        ]
        return [p for p in paths if os.path.exists(p)]

    def start_shield(self, scan_callback: Callable[[str], Optional[dict]], paths: Optional[List[str]] = None) -> bool:
        if not WATCHDOG_AVAILABLE:
            return False

        with self._lock:
            if self.is_active:
                return True

            watch_dirs = paths or self.get_default_watch_dirs()
            self.monitored_paths = watch_dirs
            self.observer = Observer()

            def handle_new_file(file_path: str):
                try:
                    result = scan_callback(file_path)
                    if result and self.on_threat_detected:
                        self.on_threat_detected(result)
                except Exception as e:
                    print(f"[RealtimeShield Error] {e}")

            handler = ShieldHandler(on_file_created=handle_new_file)
            for path in watch_dirs:
                try:
                    self.observer.schedule(handler, path, recursive=False)
                except Exception:
                    pass

            self.observer.start()
            self.is_active = True
            return True

    def stop_shield(self):
        with self._lock:
            if self.is_active and self.observer:
                self.observer.stop()
                self.observer.join(timeout=2)
                self.observer = None
                self.is_active = False

    def get_status(self) -> dict:
        with self._lock:
            return {
                "is_active": self.is_active,
                "monitored_paths": self.monitored_paths,
                "watchdog_available": WATCHDOG_AVAILABLE
            }
