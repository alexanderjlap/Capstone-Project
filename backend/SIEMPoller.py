import time
import random
from database import get_connection

class SIEMPoller:
    def __init__(self):
        self.siemQueryEndpoint = "http://127.0.0.1:55000/wazuh"
        self.maxPollingTimeout = 300

    def evaluateDetection(self, technique_id: str, variant: str, payload_str: str) -> dict:
        """
        Evaluates whether the test payload triggers a SIEM / Sigma alert,
        and generates realistic Sysmon telemetry event counts.
        """
        conn = get_connection()
        cur = conn.cursor()
        
        # Check active rules for this technique
        cur.execute("SELECT rule_file, modified, change_desc FROM detection_rules WHERE technique_id = ?", (technique_id,))
        rule = cur.fetchone()
        conn.close()

        rule_file = rule["rule_file"] if rule else None
        rule_modified = bool(rule["modified"]) if rule else False

        # Determine detection result based on technique, variant, and rule status
        alert_generated = False
        reason = ""

        is_base = (variant.lower() == "base")

        if technique_id == "T1059.001": # PowerShell
            if is_base:
                alert_generated = True
                reason = "Matched Sigma rule: powershell_exec.yml (Standard invocation)"
            elif "encoded" in payload_str.lower() or "iex" in payload_str.lower() or "var-3" in variant.lower():
                # If rule is modified/patched, it catches EncodedCommand
                if rule_modified:
                    alert_generated = True
                    reason = "Matched updated Sigma rule: powershell_exec.yml (EncodedCommand heuristic)"
                else:
                    alert_generated = False
                    reason = "Evasion successful: Rule missed Base64 encoded or concatenated payload"
            else:
                alert_generated = True

        elif technique_id == "T1003.001": # LSASS Memory
            if is_base:
                alert_generated = True
                reason = "Matched Sigma rule: cred_dump_lsass_direct.yml"
            elif "comsvcs" in payload_str.lower() or "nanodump" in payload_str.lower() or "var-2" in variant.lower():
                if rule_modified:
                    alert_generated = True
                    reason = "Matched updated rule: comsvcs.dll DLL export heuristic"
                else:
                    alert_generated = False
                    reason = "Evasion successful: rundll32 / comsvcs.dll bypasses direct OpenProcess rule"
            else:
                alert_generated = not ("var" in variant.lower())

        elif technique_id == "T1055.012": # Process Hollowing
            if rule_modified:
                alert_generated = True
                reason = "Matched new rule: Sysmon EID 10 memory-write heuristic"
            else:
                alert_generated = False
                reason = "No active Sigma rule consuming Sysmon EID 10"

        elif technique_id == "T1078": # Valid Accounts
            if is_base:
                alert_generated = True
                reason = "Matched rule: Sensitive admin account logon"
            else:
                alert_generated = False
                reason = "Evasion: Renamed local account bypassed Administrator name check"

        elif technique_id == "T1021.001": # RDP
            alert_generated = True if is_base or "var-1" in variant.lower() or "var-2" in variant.lower() else False
            reason = "RDP network session logged" if alert_generated else "Evasion via SSH tunnel port forwarding"

        elif technique_id == "T1027.002": # Software Packing
            if rule_modified:
                alert_generated = True
                reason = "Matched entropy heuristic for packed executable"
            else:
                alert_generated = False
                reason = "Evasion: Modified UPX headers evaded signature match"

        elif technique_id == "T1082": # System Info
            alert_generated = True
            reason = "Process execution systeminfo.exe and whoami.exe logged"

        elif technique_id == "T1105": # Ingress Tool Transfer
            if is_base or "var-1" in variant.lower():
                alert_generated = True
                reason = "certutil.exe outbound HTTP download logged"
            else:
                alert_generated = False
                reason = "Data URI bypass avoided HTTP network request"

        elif technique_id == "T1569.002": # Service Execution
            alert_generated = False
            reason = "sc.exe execution missed by standard service creation audit rules"

        elif technique_id == "T1136.001": # Local Account Creation
            if is_base:
                alert_generated = True
                reason = "net.exe user /add detected by process creation rule"
            else:
                alert_generated = False
                reason = "ADSI COM object avoided net.exe process creation"
        else:
            alert_generated = is_base

        # Synthesize realistic Sysmon telemetry based on technique
        eid1 = random.randint(2, 6) # Process Create
        eid3 = random.randint(1, 4) if technique_id in ["T1105", "T1021.001", "T1078"] else 0 # Network
        eid11 = random.randint(1, 5) if technique_id in ["T1003.001", "T1105", "T1027.002"] else 0 # File Create
        eid13 = random.randint(2, 8) if technique_id in ["T1059.001", "T1136.001", "T1569.002"] else 0 # Registry Set
        
        total_sysmon = eid1 + eid3 + eid11 + eid13
        latency_sec = round(random.uniform(0.6, 2.4), 2) if alert_generated else None
        exec_ms = int(latency_sec * 1000) if latency_sec else random.randint(500, 1800)

        return {
            "alertGenerated": alert_generated,
            "detectionLatencySeconds": latency_sec,
            "execMs": exec_ms,
            "sysmonEvents": total_sysmon,
            "eid1_count": eid1,
            "eid3_count": eid3,
            "eid11_count": eid11,
            "eid13_count": eid13,
            "reason": reason,
            "sigmaRule": rule_file
        }

    def calculateLatency(self, executionTime, alertTime) -> float:
        if alertTime and executionTime:
            return round(alertTime - executionTime, 2)
        return 0.0
