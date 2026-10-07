"""
Aegis Defender Pro - Process & Memory Behavior Inspector
Cross-platform active process scanner, commandline heuristic analyzer, and threat termination.
"""

import os
import re
import signal
import subprocess
import sys
from typing import Dict, List, Optional, Any

# Signatures of high-risk process names & suspicious commandline arguments
SUSPICIOUS_PROCESS_NAMES = [
    "xmrig", "minerd", "ethminer", "ccminer", "mimikatz", "procdump",
    "chisel", "ngrok", "socat", "meterpreter", "hydra", "aircrack"
]

SUSPICIOUS_CMD_PATTERNS = [
    (r"(?i)powershell(\.exe)?\s+(-[eE][a-zA-Z]*|-EncodedCommand)", "PowerShell Encoded Command", "High"),
    (r"(?i)(/bin/bash|/bin/sh)\s+-i\s+>&?\s*/dev/tcp/", "Interactive Reverse Shell Socket", "Critical"),
    (r"(?i)curl\s+.*\|\s*(sh|bash|python|perl)", "Remote Shell Script Pipe Execution", "High"),
    (r"(?i)wget\s+.*\|\s*(sh|bash|python|perl)", "Remote Shell Script Pipe Execution", "High"),
    (r"(?i)osascript\s+-e\s+.*with\s+administrator\s+privileges", "macOS Admin Prompt Impersonation", "High"),
    (r"(?i)python.*-c.*import\s+(socket|pty)", "Inline Python Reverse Shell / Socket", "Critical"),
    (r"(?i)stratum\+tcp://", "Cryptomining Pool Connection", "Medium"),
    (r"(?i)nc(\.traditional)?\s+.*-e\s+(/bin/sh|/bin/bash|cmd\.exe)", "Netcat Shell Execution", "Critical")
]

class ProcessMonitor:
    """Monitors live OS processes and inspects command lines for adversarial behaviors."""

    def __init__(self):
        self.is_windows = sys.platform.startswith("win")

    def get_running_processes(self) -> List[Dict[str, Any]]:
        """Enumerates running processes with PID, command line, memory, CPU, and risk score."""
        processes = []
        if self.is_windows:
            processes = self._get_windows_processes()
        else:
            processes = self._get_unix_processes()

        # Score and sort processes by risk (Critical/High first, then CPU)
        for proc in processes:
            self._assess_process_risk(proc)

        severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Clean": 0}
        processes.sort(key=lambda p: (severity_rank.get(p.get("risk", "Clean"), 0), p.get("cpu", 0.0)), reverse=True)
        return processes

    def _get_unix_processes(self) -> List[Dict[str, Any]]:
        """Parses macOS and Linux processes via ps."""
        procs = []
        try:
            # pid, ppid, %cpu, %mem, user, command
            cmd = ["ps", "-eo", "pid,ppid,%cpu,%mem,user,command"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
            lines = output.strip().split("\n")
            if not lines:
                return procs

            # Skip header line
            for line in lines[1:]:
                parts = line.strip().split(None, 5)
                if len(parts) >= 6:
                    try:
                        pid = int(parts[0])
                        ppid = int(parts[1])
                        cpu = float(parts[2])
                        mem = float(parts[3])
                        user = parts[4]
                        command = parts[5]

                        # Skip kernel idle / aegis processes themselves if desired
                        procs.append({
                            "pid": pid,
                            "ppid": ppid,
                            "cpu": cpu,
                            "memory": mem,
                            "user": user,
                            "command": command,
                            "name": os.path.basename(command.split()[0]) if command else "unknown"
                        })
                    except (ValueError, IndexError):
                        continue
        except Exception as e:
            print(f"[ProcessMonitor] Error listing unix processes: {e}")

        return procs

    def _get_windows_processes(self) -> List[Dict[str, Any]]:
        """Parses Windows processes via tasklist or wmic/powershell."""
        procs = []
        try:
            cmd = ["powershell", "-NoProfile", "-Command",
                   "Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet | ConvertTo-Json"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
            import json
            data = json.loads(output)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                procs.append({
                    "pid": item.get("Id", 0),
                    "ppid": 0,
                    "cpu": round(item.get("CPU", 0.0) or 0.0, 1),
                    "memory": round((item.get("WorkingSet", 0) or 0) / (1024 * 1024), 1),
                    "user": "System/User",
                    "command": item.get("ProcessName", "unknown"),
                    "name": item.get("ProcessName", "unknown")
                })
        except Exception as e:
            print(f"[ProcessMonitor] Error listing windows processes: {e}")
        return procs

    def _assess_process_risk(self, proc: Dict[str, Any]):
        """Evaluates commandline and binary name for malware indicators."""
        name_lower = proc.get("name", "").lower()
        cmd_str = proc.get("command", "")

        proc["risk"] = "Clean"
        proc["indicators"] = []

        # Check known malicious process names
        for bad_name in SUSPICIOUS_PROCESS_NAMES:
            if bad_name in name_lower:
                proc["risk"] = "High"
                proc["indicators"].append(f"Known Threat Binary Name: {bad_name}")

        # Check suspicious commandline regex patterns
        for pattern, indicator, severity in SUSPICIOUS_CMD_PATTERNS:
            if re.search(pattern, cmd_str):
                proc["risk"] = severity
                proc["indicators"].append(indicator)

    def terminate_process(self, pid: int) -> Dict[str, Any]:
        """Safely terminates an untrusted or rogue process."""
        try:
            if pid <= 1:
                return {"success": False, "error": "Cannot terminate init/launchd system processes."}

            if self.is_windows:
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=True)
            else:
                os.kill(pid, signal.SIGTERM)
                # If still alive, force SIGKILL
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass

            return {"success": True, "message": f"Process {pid} terminated successfully."}
        except PermissionError:
            return {"success": False, "error": f"Insufficient privileges to terminate PID {pid}. Run as administrator/root."}
        except ProcessLookupError:
            return {"success": True, "message": f"Process {pid} already exited."}
        except Exception as e:
            return {"success": False, "error": str(e)}
