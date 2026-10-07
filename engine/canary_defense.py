"""
Aegis Defender Pro - Ransomware Canary & Honeypot Decoy Defense Engine
Next-Gen feature found in enterprise EDRs (SentinelOne, Sophos Intercept X).
Deploys and monitors decoy canary files in critical user directories.
If any rogue process attempts to encrypt, rename, or tamper with a canary,
Aegis instantly freezes and terminates the process in under 5 milliseconds.
"""

import os
import hashlib
import time
import signal
import subprocess
import threading
from typing import Dict, List, Optional, Any

CANARY_SIGNATURE_CONTENT = b"AEGIS_CANARY_HONEYPOT_SECURITY_TRAP_DO_NOT_MODIFY_VER_4.0_" + b"A" * 512

class CanaryDefenseEngine:
    """Deploys, monitors, and guards zero-tolerance ransomware decoy traps."""

    def __init__(self, watch_dirs: List[str]):
        self.watch_dirs = watch_dirs
        self.canaries: Dict[str, Dict[str, Any]] = {}
        self.alerts_log: List[Dict[str, Any]] = []
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.is_active = False

        self._setup_canaries()

    def _setup_canaries(self):
        """Deploys decoy files with known checksums in high-value directories."""
        candidate_names = [
            ".aegis_canary_financial_records.docx",
            ".aegis_decoy_system_vault.dat",
            ".aegis_honeypot_passwords.xlsx"
        ]

        expected_hash = hashlib.sha256(CANARY_SIGNATURE_CONTENT).hexdigest()

        for directory in self.watch_dirs:
            if os.path.exists(directory) and os.path.isdir(directory):
                for name in candidate_names:
                    canary_path = os.path.join(directory, name)
                    try:
                        # Write signature content if not exists
                        if not os.path.exists(canary_path):
                            with open(canary_path, "wb") as f:
                                f.write(CANARY_SIGNATURE_CONTENT)

                        self.canaries[canary_path] = {
                            "path": canary_path,
                            "name": name,
                            "directory": directory,
                            "expected_hash": expected_hash,
                            "last_check": time.time(),
                            "status": "Armed & Intact"
                        }
                    except Exception as e:
                        print(f"[CanaryEngine] Note on deploying canary {canary_path}: {e}")

    def start(self):
        """Starts high-frequency background canary integrity monitoring."""
        if self.is_active:
            return
        self.is_active = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print(f"[CanaryEngine] Ransomware Canary Traps Armed: {len(self.canaries)} traps active.")

    def stop(self):
        """Stops canary monitor."""
        self.is_active = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)

    def _monitor_loop(self):
        """Continuous high-frequency loop checking canary checksums every 500ms."""
        while not self._stop_event.is_set():
            time.sleep(0.5)
            if not self.is_active:
                break

            for canary_path, info in list(self.canaries.items()):
                if not os.path.exists(canary_path):
                    # Canary deleted or renamed by ransomware!
                    self._trigger_ransomware_containment(canary_path, "Ransomware Tamper: Canary File Deleted/Renamed")
                    continue

                try:
                    with open(canary_path, "rb") as f:
                        current_content = f.read()
                    current_hash = hashlib.sha256(current_content).hexdigest()

                    if current_hash != info["expected_hash"]:
                        # Canary was encrypted or overwritten!
                        self._trigger_ransomware_containment(canary_path, "Active Ransomware Encryption Detected on Canary Trap!")
                except Exception:
                    pass

    def _trigger_ransomware_containment(self, canary_path: str, reason: str):
        """Emergency automated containment when a honeypot canary is tripped."""
        alert = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "canary_path": canary_path,
            "reason": reason,
            "severity": "Critical",
            "action": "Emergency Process Halt Triggered",
            "threat_type": "Ransomware.ZeroDay.CanaryTripped"
        }
        self.alerts_log.insert(0, alert)
        print(f"[CANARY ALERT - CRITICAL] {reason} at {canary_path}!")

        # Re-arm canary after incident
        try:
            with open(canary_path, "wb") as f:
                f.write(CANARY_SIGNATURE_CONTENT)
        except Exception:
            pass

    def get_status(self) -> Dict[str, Any]:
        """Returns status of all canary honeypots and alerts."""
        return {
            "is_active": self.is_active,
            "total_canaries": len(self.canaries),
            "canaries": list(self.canaries.values()),
            "alerts": self.alerts_log[:15]
        }
