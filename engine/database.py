"""
Aegis Defender Pro - Threat Intelligence & Signature Database
Cross-platform signature definitions, YARA-style heuristic rules, and vulnerability metadata.
"""

import json
import os
import re
from typing import Dict, List, Optional, Any

# Standard EICAR test string definition (harmless industry-standard antivirus verification)
EICAR_TEST_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Known Threat Hashes Database (SHA-256 and MD5)
# Includes prominent ransomware, banking trojans, backdoors, miners, and test signatures
DEFAULT_HASH_SIGNATURES: Dict[str, Dict[str, Any]] = {
    # Standard Antivirus Validation
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "name": "EICAR-Test-Signature.Standard",
        "type": "Test File",
        "severity": "Low",
        "category": "EICAR Test",
        "description": "Standard European Institute for Computer Antivirus Research test verification string.",
        "remediation": "Safe to delete. Created for testing antivirus detection capability."
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "name": "EICAR-Test-Signature.MD5",
        "type": "Test File",
        "severity": "Low",
        "category": "EICAR Test",
        "description": "Standard EICAR MD5 hash test definition.",
        "remediation": "Safe to delete. Created for testing antivirus detection."
    },
    # Ransomware
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c": {
        "name": "Ransom.WannaCry.A!ms017-010",
        "type": "Ransomware",
        "severity": "Critical",
        "category": "WannaCry",
        "description": "WannaCryptor worm exploiting SMBv1 MS17-010 to encrypt local drives.",
        "remediation": "Isolate machine immediately, patch MS17-010 SMB, do not pay ransom."
    },
    "8ac83685dd2a1215b49d564175ac210cfc089cb798038b321c169970997c4f03": {
        "name": "Ransom.Ryuk.Gen!enc",
        "type": "Ransomware",
        "severity": "Critical",
        "category": "Ryuk",
        "description": "Targeted enterprise ransomware known for manual lateral movement.",
        "remediation": "Quarantine host, audit Active Directory domain admin credentials."
    },
    "c07a3c31e6c0b9d6a36f7351666c1b3f9479bbf78988220f8fa5b03f024ec447": {
        "name": "Ransom.DarkSide.LinuxVM",
        "type": "Ransomware",
        "severity": "Critical",
        "category": "DarkSide",
        "description": "Ransomware used in high-profile pipeline disruptions targeting ESXi/Windows.",
        "remediation": "Sever network connection, restore from offline immutable backups."
    },
    "3b84db968efbd53a3c26786a51d95c52c6f376cfb16d1f93ee74f4b9319e0958": {
        "name": "Ransom.Locky.Payload",
        "type": "Ransomware",
        "severity": "Critical",
        "category": "Locky",
        "description": "Prolific spam-distributed ransomware utilizing RSA-2048 encryption.",
        "remediation": "Immediate quarantine and containment."
    },
    # Trojans & Infostealers
    "4f7b6059d43ecdfd90a597a7a2a07c393845b583907c1e5509a7b539c3ee59c4": {
        "name": "Trojan.Emotet.ModularDropper",
        "type": "Trojan",
        "severity": "High",
        "category": "Emotet",
        "description": "Advanced polymorphic banking trojan and malware distribution loader.",
        "remediation": "Rotate all saved passwords and revoke session tokens."
    },
    "a93798cf0c377dbbc29e1ebba5e3d7a8d5f30e6205763a13a8f5536412f7a4a9": {
        "name": "HackTool.Win64.Mimikatz.SE",
        "type": "HackTool",
        "severity": "High",
        "category": "Credential Stealer",
        "description": "Extracts plaintext passwords, hash digests, and Kerberos tickets from memory.",
        "remediation": "Audit local security authority subsystem (LSASS) and enable Credential Guard."
    },
    "f52e505a4153a47980590861c8a1e351834e565ad71d234676100c5c46440db7": {
        "name": "Backdoor.AsyncRAT.C2Client",
        "type": "Backdoor / RAT",
        "severity": "High",
        "category": "AsyncRAT",
        "description": "Remote Access Trojan with keylogging, screen capture, and dynamic C2 callback.",
        "remediation": "Quarantine binary and inspect scheduled tasks / startup run keys."
    },
    # macOS Specific Threats
    "9186646b5a3bb4cd4f386b6a69fb5bb089bbff7d976be3239e80e30467f7ffb5": {
        "name": "Spyware.Apple.Pegasus.Loader",
        "type": "Spyware / APT",
        "severity": "Critical",
        "category": "Pegasus",
        "description": "Sophisticated commercial spyware targeting mobile and macOS environments.",
        "remediation": "Factory device reset and review device management profiles."
    },
    "7d1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a": {
        "name": "OSX.Shlayer.InstallerDrop",
        "type": "Adware / Dropper",
        "severity": "Medium",
        "category": "Shlayer",
        "description": "Deceptive fake Flash installer dropping unwanted system extensions on macOS.",
        "remediation": "Remove fake installer and inspect /Library/LaunchAgents."
    },
    "e8f47b2c9a103d7c5885f8bfd955a6d59b3628e4e7e65123d4206e127926b01e": {
        "name": "Botnet.Mirai.TelnetScanner",
        "type": "Botnet / Worm",
        "severity": "High",
        "category": "Mirai",
        "description": "Linux/Unix ELF scanner harvesting default IoT credentials for DDoS.",
        "remediation": "Kill process, block outbound telnet/SSH brute force."
    }
}

# Heuristic YARA-style Detection Rules
# Inspects content patterns, shell commands, obfuscated scripts, and binary artifacts
DEFAULT_HEURISTIC_RULES: List[Dict[str, Any]] = [
    {
        "id": "RULE-EICAR-REGEX",
        "name": "Heuristic.Test.EICARString",
        "pattern": r"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*",
        "severity": "Low",
        "category": "Test Verification",
        "description": "Detected plain or embedded EICAR test string signature."
    },
    {
        "id": "RULE-PS-OBFUSCATION",
        "name": "Heuristic.Script.PowerShellDownloadCradle",
        "pattern": r"(?i)(Invoke-Expression|IEX)\s*\(.*(New-Object\s+Net\.WebClient|DownloadString|DownloadFile)\)",
        "severity": "High",
        "category": "Script Dropper",
        "description": "PowerShell in-memory download cradle executing remote untrusted payloads."
    },
    {
        "id": "RULE-PS-ENCODED",
        "name": "Heuristic.Script.PowerShellEncodedCommand",
        "pattern": r"(?i)powershell(\.exe)?\s+(-[eE][a-zA-Z]*|-EncodedCommand)\s+[A-Za-z0-9+/=]{30,}",
        "severity": "High",
        "category": "Obfuscated Command",
        "description": "Base64-encoded PowerShell execution command commonly used to bypass commandline telemetry."
    },
    {
        "id": "RULE-MACOS-PRIV-ESCALATION",
        "name": "Heuristic.macOS.PromptSpoofing",
        "pattern": r"(?i)osascript\s+-e\s+['\"].*with\s+administrator\s+privileges['\"]",
        "severity": "High",
        "category": "Privilege Escalation",
        "description": "AppleScript osascript prompt spoofing requesting administrative authorization."
    },
    {
        "id": "RULE-REVERSE-SHELL-BASH",
        "name": "Heuristic.Unix.BashReverseShell",
        "pattern": r"(?i)(/bin/(bash|sh|zsh)\s+-i\s+>&?\s*/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+|exec\s+\d+<>/dev/tcp/)",
        "severity": "Critical",
        "category": "Reverse Shell",
        "description": "Interactive bash/sh reverse shell connecting back over TCP socket."
    },
    {
        "id": "RULE-REVERSE-SHELL-PYTHON",
        "name": "Heuristic.Python.SocketReverseShell",
        "pattern": r"(?i)import\s+(socket|pty|subprocess)[\s\S]*?(socket\.socket\(|pty\.spawn\(['\"]/bin/(sh|bash)['\"]\))",
        "severity": "Critical",
        "category": "Reverse Shell",
        "description": "Python interactive socket payload opening pty shell or pipe to remote endpoint."
    },
    {
        "id": "RULE-RANSOMWARE-NOTE",
        "name": "Heuristic.Ransomware.ExtortionNote",
        "pattern": r"(?i)(all\s+your\s+files\s+have\s+been\s+encrypted|pay\s+bitcoin\s+to\s+decrypt|README_RESTORE_FILES|DECRYPT_INFO\.(txt|html)|send\s+0\.\d+\s+BTC)",
        "severity": "Critical",
        "category": "Ransomware Note",
        "description": "Extortion / ransom note indicators instructing user to pay cryptocurrency for decryption keys."
    },
    {
        "id": "RULE-WEBSHELL-EVAL",
        "name": "Heuristic.WebShell.PHPBackdoor",
        "pattern": r"(?i)(eval\s*\(\s*base64_decode\s*\(\s*\$_(POST|GET|REQUEST)|assert\s*\(\s*\$_(POST|GET))",
        "severity": "High",
        "category": "Web Shell",
        "description": "PHP eval/assert backdoor receiving and executing unauthenticated payloads."
    },
    {
        "id": "RULE-CRYPTO-MINER-STR",
        "name": "Heuristic.Miner.CryptonightPool",
        "pattern": r"(?i)(stratum\+tcp://|supportxmr\.com|hashvault\.pro|minexmr\.com|donate-level=\d+)",
        "severity": "Medium",
        "category": "Cryptominer",
        "description": "Monero/Cryptonight mining pool connection strings and miner configuration."
    },
    {
        "id": "RULE-WINDOWS-LSASS-DUMP",
        "name": "Heuristic.Win.LSASSDumpCommand",
        "pattern": r"(?i)(procdump(\.exe)?\s+-ma\s+lsass|rundll32(\.exe)?\s+comsvcs(\.dll)?,?MiniDump\s+\d+)",
        "severity": "Critical",
        "category": "Credential Access",
        "description": "LSASS memory dumping technique used to extract Windows credential hashes."
    }
]

class ThreatDatabase:
    """Manages hash signatures, heuristic rules, scan records, and custom user definitions."""

    def __init__(self, storage_dir: str):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)
        self.custom_hashes_file = os.path.join(self.storage_dir, "custom_hashes.json")
        self.custom_rules_file = os.path.join(self.storage_dir, "custom_rules.json")
        self.history_file = os.path.join(self.storage_dir, "scan_history.json")

        self.hash_signatures: Dict[str, Dict[str, Any]] = dict(DEFAULT_HASH_SIGNATURES)
        self.heuristic_rules: List[Dict[str, Any]] = list(DEFAULT_HEURISTIC_RULES)
        self.scan_history: List[Dict[str, Any]] = []

        self._load_custom_data()
        self._load_history()

    def _load_custom_data(self):
        """Loads user-added hashes and rules from disk."""
        if os.path.exists(self.custom_hashes_file):
            try:
                with open(self.custom_hashes_file, "r", encoding="utf-8") as f:
                    custom = json.load(f)
                    self.hash_signatures.update(custom)
            except Exception as e:
                print(f"[Database] Error reading custom hashes: {e}")

        if os.path.exists(self.custom_rules_file):
            try:
                with open(self.custom_rules_file, "r", encoding="utf-8") as f:
                    custom = json.load(f)
                    self.heuristic_rules.extend(custom)
            except Exception as e:
                print(f"[Database] Error reading custom rules: {e}")

    def _load_history(self):
        """Loads scan records history."""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, "r", encoding="utf-8") as f:
                    self.scan_history = json.load(f)
            except Exception:
                self.scan_history = []

    def save_history(self):
        """Persists scan records to file."""
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self.scan_history[-500:], f, indent=2)  # Keep last 500 records
        except Exception as e:
            print(f"[Database] Failed to save history: {e}")

    def add_scan_record(self, record: Dict[str, Any]):
        """Adds a completed scan log entry."""
        self.scan_history.insert(0, record)
        self.save_history()

    def add_custom_hash(self, file_hash: str, threat_info: Dict[str, Any]) -> bool:
        """Adds a custom user-defined hash to the signature database."""
        cleaned_hash = file_hash.strip().lower()
        if len(cleaned_hash) not in (32, 64):  # MD5 or SHA-256
            return False
        self.hash_signatures[cleaned_hash] = threat_info
        try:
            custom_data = {}
            if os.path.exists(self.custom_hashes_file):
                with open(self.custom_hashes_file, "r", encoding="utf-8") as f:
                    custom_data = json.load(f)
            custom_data[cleaned_hash] = threat_info
            with open(self.custom_hashes_file, "w", encoding="utf-8") as f:
                json.dump(custom_data, f, indent=2)
            return True
        except Exception as e:
            print(f"[Database] Failed to save custom hash: {e}")
            return False

    def add_custom_rule(self, rule_name: str, pattern: str, severity: str, category: str, description: str) -> bool:
        """Compiles and registers a new heuristic regex rule."""
        try:
            re.compile(pattern)  # Test regex validity
            rule_entry = {
                "id": f"RULE-CUSTOM-{len(self.heuristic_rules) + 1}",
                "name": rule_name,
                "pattern": pattern,
                "severity": severity,
                "category": category,
                "description": description
            }
            self.heuristic_rules.append(rule_entry)

            custom_data = []
            if os.path.exists(self.custom_rules_file):
                with open(self.custom_rules_file, "r", encoding="utf-8") as f:
                    custom_data = json.load(f)
            custom_data.append(rule_entry)
            with open(self.custom_rules_file, "w", encoding="utf-8") as f:
                json.dump(custom_data, f, indent=2)
            return True
        except Exception as e:
            print(f"[Database] Failed to compile custom rule: {e}")
            return False

    def lookup_hash(self, sha256_hash: str, md5_hash: str = "") -> Optional[Dict[str, Any]]:
        """Checks both SHA256 and MD5 against the signature database."""
        sha_match = self.hash_signatures.get(sha256_hash.lower())
        if sha_match:
            return sha_match
        if md5_hash:
            md5_match = self.hash_signatures.get(md5_hash.lower())
            if md5_match:
                return md5_match
        return None

    def get_all_signatures(self) -> Dict[str, Any]:
        """Returns database signature metadata."""
        return {
            "total_hashes": len(self.hash_signatures),
            "total_rules": len(self.heuristic_rules),
            "hashes": self.hash_signatures,
            "rules": self.heuristic_rules
        }
