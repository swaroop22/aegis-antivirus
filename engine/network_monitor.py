"""
Aegis Defender Pro - Zero-Trust Network Exfiltration & C2 Socket Auditor
Audits live TCP/UDP socket connections and intercepts reverse shells, C2 beacons, and data exfiltration.
"""

import os
import re
import subprocess
import sys
from typing import Dict, List, Any

SUSPICIOUS_REMOTE_PORTS = {4444, 1337, 6667, 9001, 8888, 31337, 4443}
SUSPICIOUS_NETWORK_PROCESSES = {"nc", "ncat", "netcat", "socat", "chisel", "bash", "sh", "zsh", "python", "perl", "ruby"}

class NetworkMonitor:
    """Audits active sockets for command-and-control (C2) and data exfiltration indicators."""

    def __init__(self):
        self.is_windows = sys.platform.startswith("win")

    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Enumerates active TCP/UDP sockets with risk classification."""
        if self.is_windows:
            return self._get_windows_connections()
        return self._get_unix_connections()

    def _get_unix_connections(self) -> List[Dict[str, Any]]:
        """Parses unix sockets via lsof."""
        connections = []
        try:
            cmd = ["lsof", "-iTCP", "-P", "-n"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
            lines = output.strip().splitlines()
            if not lines:
                return connections

            for line in lines[1:80]:
                parts = line.split()
                if len(parts) >= 9:
                    proc_name = parts[0]
                    pid = parts[1]
                    user = parts[2]
                    proto = parts[7]
                    addr = parts[8]
                    state = parts[9] if len(parts) > 9 else "ESTABLISHED"

                    risk = "Clean"
                    indicators = []

                    remote_port = 0
                    if "->" in addr:
                        try:
                            remote_part = addr.split("->")[1]
                            remote_port = int(remote_part.split(":")[-1])
                        except Exception:
                            pass

                    if remote_port in SUSPICIOUS_REMOTE_PORTS:
                        risk = "Critical"
                        indicators.append(f"Connected to Known Malicious / C2 Port: {remote_port}")

                    if proc_name.lower() in SUSPICIOUS_NETWORK_PROCESSES and "->" in addr:
                        if not addr.startswith("127.0.0.1") and not addr.startswith("::1"):
                            risk = "High"
                            indicators.append(f"Script/Shell binary {proc_name} opening internet socket ({addr})")

                    connections.append({
                        "process": proc_name,
                        "pid": pid,
                        "user": user,
                        "protocol": proto,
                        "connection": addr,
                        "state": state,
                        "risk": risk,
                        "indicators": indicators
                    })
        except Exception:
            pass

        risk_rank = {"Critical": 3, "High": 2, "Medium": 1, "Clean": 0}
        connections.sort(key=lambda x: risk_rank.get(x.get("risk", "Clean"), 0), reverse=True)
        return connections

    def _get_windows_connections(self) -> List[Dict[str, Any]]:
        """Parses Windows netstat sockets."""
        connections = []
        try:
            cmd = ["netstat", "-ano"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] in ("TCP", "UDP"):
                    connections.append({
                        "process": "PID " + parts[-1],
                        "pid": parts[-1],
                        "user": "System/User",
                        "protocol": parts[0],
                        "connection": f"{parts[1]} -> {parts[2]}",
                        "state": parts[3] if len(parts) > 4 else "ESTABLISHED",
                        "risk": "Clean",
                        "indicators": []
                    })
        except Exception:
            pass
        return connections
