from .ml_engine import AIThreatScorer
"""
Aegis Defender Pro - Core File Scanner
High-performance static, heuristic, and entropy analysis engine for macOS & Windows.
"""

import hashlib
import math
import os
import re
from typing import Dict, List, Optional, Any
from .database import ThreatDatabase, EICAR_TEST_STRING

CHUNK_SIZE = 65536  # 64 KB read buffer
MAX_INSPECT_BYTES = 10 * 1024 * 1024  # Max 10MB inspection buffer for pattern analysis

class FileScanner:
    """Core malware detection engine supporting multiple detection layers."""

    def __init__(self, db: ThreatDatabase):
        self.db = db

        # Suspicious double extension pattern (masquerading attacks)
        self.suspicious_ext_regex = re.compile(
            r"\.(pdf|docx|xlsx|jpg|png|mp4|txt)\.(exe|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|scr|pif|app|sh)$",
            re.IGNORECASE
        )

        # Packed / Obfuscated section markers common in malware
        self.ai_scorer = AIThreatScorer()
        self.packer_signatures = [
            b"UPX0", b"UPX1", b"UPX2", b".aspack", b".themida", b".vmp0", b".vmp1", b"PECompact"
        ]

    def calculate_hashes(self, file_path: str, max_bytes: int = 50 * 1024 * 1024) -> Dict[str, str]:
        """Calculates MD5 and SHA-256 hashes using streaming chunks up to max_bytes."""
        hasher_sha256 = hashlib.sha256()
        hasher_md5 = hashlib.md5()
        bytes_read = 0

        with open(file_path, "rb") as f:
            while bytes_read < max_bytes:
                chunk = f.read(min(CHUNK_SIZE, max_bytes - bytes_read))
                if not chunk:
                    break
                hasher_sha256.update(chunk)
                hasher_md5.update(chunk)
                bytes_read += len(chunk)

        return {
            "sha256": hasher_sha256.hexdigest(),
            "md5": hasher_md5.hexdigest()
        }

    def calculate_entropy(self, data: bytes) -> float:
        """Calculates Shannon entropy of raw byte data (0.0 to 8.0)."""
        if not data:
            return 0.0

        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256

        for b in data:
            byte_counts[b] += 1

        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        return round(entropy, 3)

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Runs the complete multi-layer inspection pipeline on a single target file."""
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return {
                "is_threat": False,
                "file_path": file_path,
                "error": "File not found or inaccessible"
            }

        try:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)

            # 1. Compute Hashes
            hashes = self.calculate_hashes(file_path)
            sha256_val = hashes["sha256"]
            md5_val = hashes["md5"]

            # 2. Layer 1: Direct Hash Signature Matching
            known_match = self.db.lookup_hash(sha256_val, md5_val)
            if known_match:
                return {
                    "is_threat": True,
                    "threat_name": known_match["name"],
                    "threat_type": known_match["type"],
                    "severity": known_match["severity"],
                    "category": known_match["category"],
                    "file_path": file_path,
                    "file_name": file_name,
                    "file_size": file_size,
                    "sha256": sha256_val,
                    "md5": md5_val,
                    "entropy": 0.0,
                    "detection_method": "Exact Hash Signature",
                    "details": known_match["description"],
                    "remediation": known_match["remediation"]
                }

            # 3. Read sample bytes for heuristic & pattern scanning
            inspect_size = min(file_size, MAX_INSPECT_BYTES)
            with open(file_path, "rb") as f:
                raw_bytes = f.read(inspect_size)

            entropy = self.calculate_entropy(raw_bytes)

            # Layer 2: EICAR test string raw match
            if EICAR_TEST_STRING.encode("ascii", errors="ignore") in raw_bytes:
                return {
                    "is_threat": True,
                    "threat_name": "EICAR-Standard-AV-Test-Signature",
                    "threat_type": "Test Verification",
                    "severity": "Low",
                    "category": "EICAR Test",
                    "file_path": file_path,
                    "file_name": file_name,
                    "file_size": file_size,
                    "sha256": sha256_val,
                    "md5": md5_val,
                    "entropy": entropy,
                    "detection_method": "Signature Pattern Match",
                    "details": "Standard harmless EICAR antivirus test file detected.",
                    "remediation": "Safe to isolate or delete. Use to verify real-time protection triggers."
                }

            # Layer 3: Double Extension / Spoofing Check
            if self.suspicious_ext_regex.search(file_name):
                return {
                    "is_threat": True,
                    "threat_name": "Suspicious.ExtensionSpoof.Generic",
                    "threat_type": "Masquerading Attack",
                    "severity": "High",
                    "category": "Deceptive Naming",
                    "file_path": file_path,
                    "file_name": file_name,
                    "file_size": file_size,
                    "sha256": sha256_val,
                    "md5": md5_val,
                    "entropy": entropy,
                    "detection_method": "Extension Masquerade Analysis",
                    "details": f"File uses disguised double extension to impersonate documents or media: {file_name}",
                    "remediation": "Quarantine file immediately. Do not launch disguised executable."
                }

            # Layer 4: Heuristic Regex & YARA-Style Pattern Search
            # Decode with replacement to inspect text/scripts safely
            try:
                text_content = raw_bytes.decode("utf-8", errors="ignore")
            except Exception:
                text_content = ""

            for rule in self.db.heuristic_rules:
                if re.search(rule["pattern"], text_content):
                    return {
                        "is_threat": True,
                        "threat_name": rule["name"],
                        "threat_type": rule.get("category", "Heuristic"),
                        "severity": rule["severity"],
                        "category": rule.get("category", "Pattern Match"),
                        "file_path": file_path,
                        "file_name": file_name,
                        "file_size": file_size,
                        "sha256": sha256_val,
                        "md5": md5_val,
                        "entropy": entropy,
                        "detection_method": "Heuristic Rule Match",
                        "rule_id": rule.get("id"),
                        "details": rule["description"],
                        "remediation": "Isolate in quarantine and examine origin."
                    }

            # Layer 5: Binary Header & Packer Analysis (Windows PE & macOS Mach-O)
            is_pe = raw_bytes.startswith(b"MZ")
            is_macho = raw_bytes.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"))

            if is_pe or is_macho:
                # Check for known packer headers
                for packer in self.packer_signatures:
                    if packer in raw_bytes:
                        # High entropy + known packer signature = suspicious packer/crypter
                        if entropy > 7.3:
                            return {
                                "is_threat": True,
                                "threat_name": f"Suspicious.PackedExecutable.{packer.decode('ascii', errors='ignore')}",
                                "threat_type": "Obfuscated Binary",
                                "severity": "Medium",
                                "category": "Packer Detection",
                                "file_path": file_path,
                                "file_name": file_name,
                                "file_size": file_size,
                                "sha256": sha256_val,
                                "md5": md5_val,
                                "entropy": entropy,
                                "detection_method": "Binary Structure & Packer Analysis",
                                "details": f"Executable contains packed section '{packer.decode('ascii', errors='ignore')}' with abnormal entropy ({entropy}).",
                                "remediation": "Review binary signing status and origin."
                            }

                # Layer 6: Abnormal High Entropy on Executable (> 7.8 indicates encrypted payload/ransomware)
                if entropy > 7.8 and file_size > 4096:
                    return {
                        "is_threat": True,
                        "threat_name": "Heuristic.HighEntropy.PotentialCrypter",
                        "threat_type": "Suspicious Crypt / Payload",
                        "severity": "Medium",
                        "category": "Entropy Anomaly",
                        "file_path": file_path,
                        "file_name": file_name,
                        "file_size": file_size,
                        "sha256": sha256_val,
                        "md5": md5_val,
                        "entropy": entropy,
                        "detection_method": "Entropy Heuristics",
                        "details": f"File exhibits near-maximum random byte distribution (Entropy: {entropy}/8.0), characteristic of encrypted droppers or encrypted archives.",
                        "remediation": "Inspect executable origin before running."
                    }


            # Layer 7: Next-Gen AI/ML Heuristic Anomaly Scoring
            ai_eval = self.ai_scorer.analyze_file(file_path, raw_bytes, entropy)
            if ai_eval.get('ai_threat_score', 0) >= 60.0:
                return {
                    'is_threat': True,
                    'threat_name': f"ZeroDay.Anomaly.AI-{ai_eval.get('classification', 'Threat').replace(' ', '')}",
                    'threat_type': 'Zero-Day / ML Anomaly',
                    'severity': 'Critical' if ai_eval['ai_threat_score'] >= 80 else 'High',
                    'category': 'AI Feature Analysis',
                    'file_path': file_path,
                    'file_name': file_name,
                    'file_size': file_size,
                    'sha256': sha256_val,
                    'md5': md5_val,
                    'entropy': entropy,
                    'ai_threat_score': ai_eval['ai_threat_score'],
                    'ai_features': ai_eval.get('features', []),
                    'detection_method': 'AI/ML Anomaly Scoring Engine',
                    'details': f"Multi-factor AI heuristic score: {ai_eval['ai_threat_score']}%. Identifies structural and payload anomalies.",
                    'remediation': 'Isolate immediately. Inspect binary structure in Sandbox.'
                }

            # File Clean
            return {
                "is_threat": False,
                "file_path": file_path,
                "file_name": file_name,
                "file_size": file_size,
                "sha256": sha256_val,
                "md5": md5_val,
                "entropy": entropy,
                "severity": "Clean",
                "details": "No known signatures or malicious heuristics identified."
            }

        except PermissionError:
            return {
                "is_threat": False,
                "file_path": file_path,
                "error": "Permission denied reading file"
            }
        except Exception as e:
            return {
                "is_threat": False,
                "file_path": file_path,
                "error": str(e)
            }
