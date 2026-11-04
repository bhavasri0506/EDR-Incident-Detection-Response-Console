import os
import time
import socket
import json
import hashlib
from datetime import datetime
import psutil
import requests

SERVER_URL = "http://127.0.0.1:5000/api/telemetry"
LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
LOG_FILE = os.path.join(LOG_DIR, "edr_events.log")

os.makedirs(LOG_DIR, exist_ok=True)
HOSTNAME = socket.gethostname()

THREAT_PLAYBOOK = {
    "-enc": {
        "name": "Base64 Obfuscated PowerShell Execution",
        "technique": "T1059.001",
        "description": "Adversary attempted to execute encoded PowerShell commands to bypass script block logging and security controls.",
        "resolution": "1. Terminate PowerShell execution tree. 2. Decode Base64 string for intent. 3. Review parent process execution hierarchy."
    },
    "bypass": {
        "name": "Execution Policy Bypass",
        "technique": "T1562.001",
        "description": "Attempt to circumvent Windows PowerShell execution policy to run unverified scripts.",
        "resolution": "1. Enforce AppLocker/WDAC script enforcement. 2. Inspect downloaded payload artifacts. 3. Restrict execution privileges."
    },
    "mimikatz": {
        "name": "LSASS Memory Credential Dumping",
        "technique": "T1003.001",
        "description": "Adversary tried extracting plaintext passwords or Kerberos tickets directly from system memory.",
        "resolution": "1. Immediately isolate endpoint. 2. Rotate all active domain administrative credentials. 3. Enable Credential Guard."
    },
    "vssadmin": {
        "name": "Ransomware Shadow Copy Deletion",
        "technique": "T1490",
        "description": "Adversary executed vssadmin to delete Volume Shadow Copies to prevent system recovery during a ransomware infection.",
        "resolution": "1. Isolate host from LAN immediately. 2. Validate offline backup integrity. 3. Scan disk for active ransomware droppers."
    },
    "certutil": {
        "name": "Ingress Tool Transfer (Certutil LOLBin)",
        "technique": "T1105",
        "description": "Abuse of built-in certutil utility to download remote malicious binaries onto the host.",
        "resolution": "1. Block source outbound IP/domain at perimeter firewall. 2. Quarantine files dropped in Temp directory."
    },
    "whoami": {
        "name": "System Owner/User Discovery",
        "technique": "T1033",
        "description": "Reconnaissance execution to identify local user account privileges and domain context.",
        "resolution": "1. Monitor follow-up privilege escalation commands. 2. Verify account baseline behavior."
    }
}

def get_file_hash(proc):
    try:
        exe_path = proc.exe()
        if exe_path and os.path.exists(exe_path):
            sha256_hash = hashlib.sha256()
            with open(exe_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
    except Exception:
        pass
    return "UNKNOWN_HASH"

def log_to_file(payload):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(payload) + "\n")

def send_to_server(payload):
    try:
        requests.post(SERVER_URL, json=payload, timeout=2)
    except Exception:
        pass

def inspect_process(proc):
    try:
        p_info = proc.as_dict(attrs=['pid', 'name', 'cmdline'])
        pid = p_info['pid']
        name = p_info['name'] or "unknown"
        cmdline_list = p_info['cmdline'] or []
        cmdline = " ".join(cmdline_list)

        if pid <= 4 or not name:
            return

        is_threat = False
        attack_name = "Normal Process"
        mitre_id = "-"
        desc = "Standard system operation."
        resolution = "No action required."

        cmd_lower = cmdline.lower()

        for kw, intel in THREAT_PLAYBOOK.items():
            if kw in cmd_lower:
                is_threat = True
                attack_name = intel["name"]
                mitre_id = intel["technique"]
                desc = intel["description"]
                resolution = intel["resolution"]
                break

        action_status = "DETECTED"
        severity = "INFO"
        file_hash = get_file_hash(proc)

        if is_threat:
            severity = "CRITICAL"
            try:
                proc.terminate()
                action_status = "TERMINATED"
                print(f"[!] THREAT NEUTRALIZED -> Attack: {attack_name} | PID: {pid} | Hash: {file_hash[:12]}...")
            except Exception:
                action_status = "TERMINATION_FAILED"

        payload = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "host": HOSTNAME,
            "pid": pid,
            "process_name": name,
            "cmdline": cmdline if cmdline else name,
            "sha256": file_hash,
            "severity": severity,
            "status": action_status,
            "attack_name": attack_name,
            "mitre_id": mitre_id,
            "description": desc,
            "resolution": resolution
        }

        send_to_server(payload)
        log_to_file(payload)

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

def start_agent():
    print(f"[*] EDR Agent Started on Host: {HOSTNAME}")
    print("[*] Threat Intelligence & Remediation Engine Active...")
    
    count = 0
    for proc in psutil.process_iter():
        inspect_process(proc)
        count += 1
        if count >= 15:
            break

    seen_pids = set(psutil.pids())
    print("[*] Continuous endpoint surveillance active...")

    while True:
        current_pids = set(psutil.pids())
        new_pids = current_pids - seen_pids

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                inspect_process(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        seen_pids = current_pids
        time.sleep(0.3)

if __name__ == "__main__":
    start_agent()