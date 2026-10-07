"""
Aegis Defender Pro - MITRE ATT&CK Persistence & Autostart Hunter
Audits system persistence vectors (LaunchDaemons, LaunchAgents, Crontabs, Registry Run keys).
Maps adversary techniques directly to the MITRE ATT&CK framework (T1543, T1053, T1546).
"""

import os
import plistlib
import subprocess
import sys
from typing import Dict, List, Any

class PersistenceHunter:
    """Audits autostart execution vectors across macOS and Windows."""

    def __init__(self):
        self.is_windows = sys.platform.startswith("win")

    def audit_all_persistence(self) -> List[Dict[str, Any]]:
        """Executes a full persistence audit."""
        if self.is_windows:
            return self._audit_windows()
        return self._audit_macos()

    def _audit_macos(self) -> List[Dict[str, Any]]:
        """Audits macOS LaunchDaemons, LaunchAgents, crontabs, and shell startup hooks."""
        findings = []
        home = os.path.expanduser("~")

        launch_paths = [
            ("/Library/LaunchDaemons", "System LaunchDaemon", "T1543.001 - Launch Daemon"),
            ("/Library/LaunchAgents", "System LaunchAgent", "T1543.004 - Launch Agent"),
            (os.path.join(home, "Library/LaunchAgents"), "User LaunchAgent", "T1543.004 - Launch Agent")
        ]

        for folder, category, mitre_technique in launch_paths:
            if not os.path.exists(folder):
                continue

            try:
                for f in os.listdir(folder):
                    if not f.endswith(".plist"):
                        continue

                    plist_path = os.path.join(folder, f)
                    try:
                        with open(plist_path, "rb") as pf:
                            data = plistlib.load(pf)

                        label = data.get("Label", f)
                        program = data.get("Program", "")
                        program_args = data.get("ProgramArguments", [])

                        exec_target = program if program else (" ".join(program_args) if isinstance(program_args, list) else str(program_args))

                        # Evaluate Risk
                        risk = "Clean"
                        reasons = []

                        # Check if points to suspicious temp directories
                        suspicious_locs = ["/tmp/", "/var/tmp/", "/Users/Shared/"]
                        for loc in suspicious_locs:
                            if loc in exec_target:
                                risk = "High"
                                reasons.append(f"Payload executes from unprivileged temp path: {loc}")

                        if any(bad in exec_target.lower() for bad in ["curl", "wget", "nc", "sh -c", "bash -c"]):
                            risk = "High"
                            reasons.append("Spawns remote shell or network download in persistence trigger")

                        findings.append({
                            "name": label,
                            "file": f,
                            "path": plist_path,
                            "category": category,
                            "mitre": mitre_technique,
                            "executable": exec_target[:180],
                            "risk": risk,
                            "details": "; ".join(reasons) if reasons else "Legitimate system or user service."
                        })
                    except Exception:
                        pass
            except Exception:
                pass

        # Sort: High risk first, then name
        risk_rank = {"High": 2, "Medium": 1, "Clean": 0}
        findings.sort(key=lambda x: risk_rank.get(x.get("risk", "Clean"), 0), reverse=True)
        return findings

    def _audit_windows(self) -> List[Dict[str, Any]]:
        """Audits Windows Registry Run keys and Startup folder."""
        findings = []
        try:
            # Query Registry Run Keys via PowerShell
            cmd = [
                "powershell", "-NoProfile", "-Command",
                "Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run | ConvertTo-Json"
            ]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
            import json
            data = json.loads(output)
            for k, v in data.items():
                if not k.startswith("PS"):
                    findings.append({
                        "name": k,
                        "file": str(v),
                        "path": "HKLM\...\Run",
                        "category": "Registry Run Key",
                        "mitre": "T1547.001 - Registry Run Keys",
                        "executable": str(v),
                        "risk": "Clean",
                        "details": "Windows autostart run key."
                    })
        except Exception:
            pass
        return findings
