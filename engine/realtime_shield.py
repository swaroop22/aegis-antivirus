"""
Aegis Defender Pro - Real-Time Filesystem Shield
Cross-platform continuous background monitor intercepting newly created or modified files.
"""

import os
import threading
import time
from typing import Dict, List, Set, Optional, Callable, Any
from .scanner import FileScanner
from .quarantine import QuarantineVault

class RealtimeShield:
    """Continuous filesystem watcher and instant threat neutralization engine."""

    def __init__(self, scanner: FileScanner, vault: QuarantineVault):
        self.scanner = scanner
        self.vault = vault

        self.is_active = False
        self.auto_quarantine = True
        self.watch_directories: Set[str] = set()

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._file_snapshots: Dict[str, float] = {}  # filepath -> mtime
        self.events_log: List[Dict[str, Any]] = []
        self._callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._lock = threading.Lock()

        # Add sensible default watch paths based on OS
        self._init_default_paths()

    def _init_default_paths(self):
        """Populates common attack drop zones (Downloads, Desktop, Temp, test_samples)."""
        home = os.path.expanduser("~")
        candidate_paths = [
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_samples")
        ]

        for p in candidate_paths:
            if os.path.exists(p) and os.path.isdir(p):
                self.watch_directories.add(os.path.abspath(p))

    def register_callback(self, cb: Callable[[Dict[str, Any]], None]):
        """Registers a listener for live threat alerts."""
        self._callbacks.append(cb)

    def _notify(self, event: Dict[str, Any]):
        """Dispatches event to registered callbacks."""
        with self._lock:
            self.events_log.insert(0, event)
            if len(self.events_log) > 200:
                self.events_log = self.events_log[:200]

        for cb in self._callbacks:
            try:
                cb(event)
            except Exception as e:
                print(f"[Shield] Callback error: {e}")

    def add_directory(self, dir_path: str) -> bool:
        """Adds a directory to the live monitor."""
        abs_p = os.path.abspath(dir_path)
        if os.path.exists(abs_p) and os.path.isdir(abs_p):
            self.watch_directories.add(abs_p)
            return True
        return False

    def remove_directory(self, dir_path: str) -> bool:
        """Removes a directory from the live monitor."""
        abs_p = os.path.abspath(dir_path)
        if abs_p in self.watch_directories:
            self.watch_directories.remove(abs_p)
            return True
        return False

    def start(self):
        """Starts real-time monitoring thread."""
        if self.is_active:
            return

        self.is_active = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print(f"[Shield] Real-Time Shield activated on {len(self.watch_directories)} directories.")

    def stop(self):
        """Stops real-time monitoring."""
        if not self.is_active:
            return

        self.is_active = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        print("[Shield] Real-Time Shield deactivated.")

    def _monitor_loop(self):
        """Background loop continuously scanning monitored directories for changes."""
        # Initial snapshot to avoid scanning entire historical directory on startup
        for d in list(self.watch_directories):
            if os.path.exists(d):
                try:
                    for root, _, files in os.walk(d):
                        for f in files:
                            # Skip quarantine vault files
                            if f.endswith(".aegis_quarantined") or ".git" in root:
                                continue
                            fp = os.path.join(root, f)
                            try:
                                self._file_snapshots[fp] = os.path.getmtime(fp)
                            except OSError:
                                pass
                except Exception:
                    pass

        while not self._stop_event.is_set():
            time.sleep(1.2)  # Low overhead cycle
            if not self.is_active:
                break

            for d in list(self.watch_directories):
                if not os.path.exists(d):
                    continue

                try:
                    for root, _, files in os.walk(d):
                        for f in files:
                            if f.endswith(".aegis_quarantined") or ".git" in root:
                                continue

                            fp = os.path.join(root, f)
                            try:
                                current_mtime = os.path.getmtime(fp)
                            except OSError:
                                continue

                            previous_mtime = self._file_snapshots.get(fp)
                            if previous_mtime is None or current_mtime > previous_mtime:
                                # New or updated file detected!
                                self._file_snapshots[fp] = current_mtime
                                self._inspect_event(fp)
                except Exception as e:
                    # Non-fatal filesystem error
                    pass

    def _inspect_event(self, file_path: str):
        """Scans a newly detected or modified file and executes defensive action."""
        if not os.path.exists(file_path):
            return

        # Give small fraction of a second for file write flush to complete
        time.sleep(0.15)
        if not os.path.exists(file_path):
            return

        
        # Whitelist internal codebase files from self-quarantine
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if os.path.abspath(file_path).startswith(project_root) and "test_samples" not in file_path:
            return

        scan_result = self.scanner.scan_file(file_path)

        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "is_threat": scan_result.get("is_threat", False),
            "threat_name": scan_result.get("threat_name", "Clean"),
            "severity": scan_result.get("severity", "Clean"),
            "detection_method": scan_result.get("detection_method", "N/A"),
            "action_taken": "Allowed"
        }

        if scan_result.get("is_threat"):
            print(f"[Shield Alert] THREAT DETECTED: {scan_result.get('threat_name')} in {file_path}")
            if self.auto_quarantine:
                q_res = self.vault.quarantine_file(file_path, scan_result)
                if q_res:
                    event["action_taken"] = "Quarantined"
                    event["quarantine_id"] = q_res["id"]
                else:
                    event["action_taken"] = "Quarantine Failed"
            else:
                event["action_taken"] = "Flagged (Manual Action Required)"

        self._notify(event)

    def get_status(self) -> Dict[str, Any]:
        """Returns shield telemetry."""
        return {
            "is_active": self.is_active,
            "auto_quarantine": self.auto_quarantine,
            "watch_directories": list(self.watch_directories),
            "tracked_files": len(self._file_snapshots),
            "total_events": len(self.events_log)
        }
