"""
Aegis Defender Pro - Scan Manager
Coordinates Quick Scans, Deep Full Scans, Custom Directory Scans, and Drag-and-Drop inspections.
Includes intelligent file-type filtering, size guards, and streaming progress updates.
"""

import os
import threading
import time
from typing import Dict, List, Optional, Any
from .scanner import FileScanner
from .quarantine import QuarantineVault
from .database import ThreatDatabase

EXCLUDED_DIRS = {
    ".git", ".svn", "node_modules", ".cache", "Library/Caches",
    "$Recycle.Bin", "System Volume Information", "Windows/WinSxS",
    "Videos & Recordings", "Movies", "Music", "Pictures", "Photos", "VirtualBox VMs"
}

SKIP_MEDIA_EXTS = {
    ".mp4", ".mov", ".mkv", ".avi", ".wmv", ".flv", ".webm", ".m4v",
    ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".tiff", ".bmp", ".heic", ".raw",
    ".iso", ".dmg", ".vmdk", ".ova", ".qcow2", ".img"
}

HIGH_RISK_EXTS = {
    ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".psm1", ".sh", ".bash", ".zsh", ".py", ".pyw", ".pl", ".rb",
    ".app", ".dylib", ".so", ".dll", ".bin", ".scr", ".pif",
    ".zip", ".tar", ".gz", ".tgz", ".rar", ".7z",
    ".pdf", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".rtf",
    ".html", ".htm", ".php", ".com"
}

class ScanManager:
    """Manages asynchronous scans with real-time streaming progress reporting."""

    def __init__(self, scanner: FileScanner, vault: QuarantineVault, db: ThreatDatabase):
        self.scanner = scanner
        self.vault = vault
        self.db = db

        self._active_thread: Optional[threading.Thread] = None
        self._cancel_requested = threading.Event()
        self._lock = threading.Lock()

        self.current_job: Dict[str, Any] = {
            "status": "idle",
            "type": None,
            "target": None,
            "progress_percent": 0,
            "scanned_files": 0,
            "threats_found": 0,
            "current_file": "",
            "threats": [],
            "start_time": 0,
            "elapsed_seconds": 0
        }

    def start_scan(self, scan_type: str = "quick", custom_path: Optional[str] = None) -> Dict[str, Any]:
        """Starts an asynchronous scan."""
        with self._lock:
            if self.current_job["status"] == "running":
                return {"success": False, "error": "A scan is already actively running."}

            self._cancel_requested.clear()
            self.current_job = {
                "status": "running",
                "type": scan_type,
                "target": custom_path or scan_type,
                "progress_percent": 1,
                "scanned_files": 0,
                "threats_found": 0,
                "current_file": "Initializing scan target list...",
                "threats": [],
                "start_time": time.time(),
                "elapsed_seconds": 0
            }

            self._active_thread = threading.Thread(
                target=self._run_scan_worker,
                args=(scan_type, custom_path),
                daemon=True
            )
            self._active_thread.start()
            return {"success": True, "message": f"{scan_type.capitalize()} scan launched."}

    def cancel_scan(self) -> Dict[str, Any]:
        """Stops the active scan."""
        with self._lock:
            if self.current_job["status"] != "running":
                return {"success": False, "error": "No scan is currently running."}

            self._cancel_requested.set()
            self.current_job["status"] = "cancelled"
            self.current_job["current_file"] = "Scan cancelled by user."
            return {"success": True, "message": "Scan cancellation signal sent."}

    def get_progress(self) -> Dict[str, Any]:
        """Returns live scan progress snapshot."""
        with self._lock:
            snapshot = dict(self.current_job)
            if snapshot["status"] == "running" and snapshot["start_time"] > 0:
                snapshot["elapsed_seconds"] = round(time.time() - snapshot["start_time"], 1)
            return snapshot

    def _get_target_paths(self, scan_type: str, custom_path: Optional[str]) -> List[str]:
        """Determines root directories to scan based on selected scan profile."""
        home = os.path.expanduser("~")
        workspace_base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        if scan_type == "custom" and custom_path:
            return [os.path.abspath(custom_path)] if os.path.exists(custom_path) else []

        if scan_type == "quick":
            paths = [
                os.path.join(workspace_base, "test_samples"),
                os.path.join(home, "Downloads"),
                os.path.join(home, "Desktop")
            ]
            return [p for p in paths if os.path.exists(p)]

        # Deep / Full scan: scans workspace, downloads, desktop, documents
        deep_paths = [
            workspace_base,
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Documents")
        ]
        return [p for p in deep_paths if os.path.exists(p)]

    def _collect_files_to_scan(self, targets: List[str], scan_type: str) -> List[str]:
        """Rapidly collects files with depth and extension filtering to prevent hanging on media."""
        files_to_scan = []
        max_files = 300 if scan_type == "quick" else 2000
        max_size_bytes = 25 * 1024 * 1024 if scan_type == "quick" else 100 * 1024 * 1024

        for target in targets:
            if self._cancel_requested.is_set() or len(files_to_scan) >= max_files:
                break

            if os.path.isfile(target):
                files_to_scan.append(target)
                continue

            target_depth = target.rstrip(os.path.sep).count(os.path.sep)
            max_depth = 2 if scan_type == "quick" else 5

            for root, dirs, files in os.walk(target):
                if self._cancel_requested.is_set() or len(files_to_scan) >= max_files:
                    break

                # Depth check
                current_depth = root.count(os.path.sep) - target_depth
                if current_depth > max_depth:
                    dirs.clear()
                    continue

                # Skip heavy directories
                dirs[:] = [
                    d for d in dirs
                    if d not in EXCLUDED_DIRS
                    and not d.startswith(".")
                    and "photo" not in d.lower()
                    and "video" not in d.lower()
                    and "music" not in d.lower()
                ]

                for f in files:
                    if self._cancel_requested.is_set() or len(files_to_scan) >= max_files:
                        break

                    if f.endswith(".aegis_quarantined") or f.endswith(".DS_Store"):
                        continue

                    ext = os.path.splitext(f)[1].lower()

                    # In quick scan: strictly skip media extensions
                    if ext in SKIP_MEDIA_EXTS:
                        continue

                    # In quick scan: if not in test_samples, prioritize high risk or top level
                    if scan_type == "quick" and "test_samples" not in root:
                        if ext not in HIGH_RISK_EXTS and current_depth > 1:
                            continue

                    fp = os.path.join(root, f)
                    try:
                        size = os.path.getsize(fp)
                        if size > max_size_bytes or size == 0:
                            continue
                    except OSError:
                        continue

                    files_to_scan.append(fp)

        return files_to_scan

    def _run_scan_worker(self, scan_type: str, custom_path: Optional[str]):
        """Background worker thread traversing files and feeding to scanner."""
        targets = self._get_target_paths(scan_type, custom_path)

        with self._lock:
            self.current_job["current_file"] = "Collecting high-risk target files..."
            self.current_job["progress_percent"] = 5

        all_files = self._collect_files_to_scan(targets, scan_type)
        total = len(all_files)

        if total == 0:
            with self._lock:
                self.current_job["status"] = "completed"
                self.current_job["progress_percent"] = 100
                self.current_job["current_file"] = "Target directory is clean (no high-risk files found)."
            return

        # 2. Iterate and scan files with continuous progress
        scanned_count = 0
        threats_found = 0

        for fp in all_files:
            if self._cancel_requested.is_set():
                break

            scanned_count += 1
            progress_pct = max(5, min(99, int((scanned_count / total) * 100)))

            with self._lock:
                self.current_job["current_file"] = os.path.basename(fp)
                self.current_job["scanned_files"] = scanned_count
                self.current_job["progress_percent"] = progress_pct

            res = self.scanner.scan_file(fp)

            if res.get("is_threat"):
                threats_found += 1
                q_meta = self.vault.quarantine_file(fp, res)
                if q_meta:
                    res["quarantine_id"] = q_meta["id"]
                    res["quarantined"] = True

                with self._lock:
                    self.current_job["threats_found"] = threats_found
                    self.current_job["threats"].append(res)

        # 3. Finalize
        with self._lock:
            if not self._cancel_requested.is_set():
                self.current_job["status"] = "completed"
                self.current_job["progress_percent"] = 100
                self.current_job["scanned_files"] = scanned_count
                self.current_job["current_file"] = f"Scan complete. Inspected {scanned_count} files."

                record = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "type": scan_type,
                    "scanned_files": scanned_count,
                    "threats_found": threats_found,
                    "duration_sec": round(time.time() - self.current_job["start_time"], 1),
                    "threats": list(self.current_job["threats"])
                }
                self.db.add_scan_record(record)
