# DetectIQ: Detection Robustness Framework

DetectIQ is an automated detection robustness framework designed to evaluate, test, and enhance SIEM and EDR detection coverage against MITRE ATT&CK techniques, evasive variations, and adversary emulation.

Developed as a senior capstone project by **Nathan Amend** and **Alex Lap**.

---

## 🌟 Key Capabilities & Use Cases

1. **Automated Test Execution (UC-1)**:
   - Automated detonation of benign adversarial payloads across MITRE ATT&CK techniques (PowerShell, LSASS Dump, Process Hollowing, RDP, LOLBins).
   - High-resolution Sysmon telemetry logging (EID 1 Process Create, EID 3 Network Connect, EID 11 File Create, EID 13 Registry Set).
   - Real-time SIEM alert evaluation and latency measurements.

2. **AI Variation Generation (UC-2)**:
   - Automated generation of novel adversarial evasion variants (AMSI bypasses, unhooked syscalls, reflective loaders, obfuscation, LOLBins).
   - Human-in-the-loop validation (Approve/Reject) with direct execution scheduling.

3. **Detection Re-Evaluation (UC-3)**:
   - Continuous re-evaluation of modified Sigma rules against known evasions and benign baselines to minimize false positives.
   - Dynamic tracking of blind spots from "open" to "patched".

4. **Coverage Matrix (UC-4)**:
   - Real-time MITRE ATT&CK detection matrix scored across base techniques and evasion variants (`VAR-1` through `VAR-4`).
   - Dynamic coverage percentage and gap analysis.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────┐
│     React 19 Frontend (Vite)    │
│  Dark Cybersecurity Dashboard   │
└────────────────┬────────────────┘
                 │ HTTP REST (JSON)
                 ▼
┌─────────────────────────────────┐       ┌───────────────────────────────┐
│       FastAPI Backend API       │ ◄───► │  SQLite / PostgreSQL Database │
│  - TestOrchestrator             │       │  - Techniques, Runs, Variants │
│  - VariationEngine              │       │  - Blind Spots, Rules, Matrix │
│  - SIEMPoller & Sigma Engine    │       └───────────────────────────────┘
└────────────────┬────────────────┘
                 │ Polling / Execution Queue
                 ▼
┌─────────────────────────────────┐
│     Windows Execution Agent     │
│  - Host Environment Probing     │
│  - Safe Subprocess Detonation   │
│  - Sysmon Telemetry Generator   │
└─────────────────────────────────┘
```

---

## 🚀 Getting Started

### 1. Prerequisites
- **Python 3.10+** (with virtual environment configured)
- **Node.js 18+** & npm

### 2. Start the Backend API
In your first terminal (from the project root):

**Git Bash (`MINGW64`):**
```bash
cd backend
./venv/Scripts/uvicorn.exe main:app --reload --port 8000
```

**PowerShell:**
```powershell
cd backend
.\venv\Scripts\uvicorn.exe main:app --reload --port 8000
```

*The FastAPI backend will automatically initialize and seed the SQLite database (`backend/detectiq.db`) with MITRE techniques, historical runs, variations, and Sigma rules.*
*Interactive API docs are available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).*

### 3. Start the Frontend Application
In a second terminal:
```bash
cd frontend
npm run dev
```
*Open [http://localhost:5173](http://localhost:5173) in your browser.*

### 4. (Optional) Run the Windows Execution Agent
To connect the live external execution agent:

**Git Bash (`MINGW64`):**
```bash
cd agent
./venv/Scripts/python.exe ExecutionAgent.py
```

**PowerShell:**
```powershell
cd agent
.\venv\Scripts\python.exe ExecutionAgent.py
```
*Note: If the agent is not running, the backend's built-in orchestration engine automatically executes and evaluates test cases so the UI is always fully interactive.*

---

## 🧭 What to Do Once You Load Up the App (Walkthrough Guide)

When you open **[http://localhost:5173](http://localhost:5173)**, you'll enter the DetectIQ console. Follow these steps to experience the complete detection lifecycle:

### Step 1: Check System Status on the Dashboard
1. Look at the top right header badge:
   - Green pulsing dot indicating **`lab-dc01 (Agent Active)`** (if the agent is running) or **`Built-in Engine`** (if running direct orchestrator mode).
2. Review the top KPI cards:
   - **Detection Coverage**: Initial baseline percentage (e.g. `46%`).
   - **ATT&CK Techniques**: Number of monitored techniques (10).
   - **Open Blind Spots**: Known detection gaps.
   - **AI Variants Generated**: Number of generated evasion variants in the repository.
3. In the **Recent Executions** table, click on any run row:
   - Look at the **Telemetry Breakdown** card below it to inspect the exact Sysmon counts (`EID 1` Process, `EID 3` Network, `EID 11` File, `EID 13` Registry) and the simulated adversarial command line.

---

### Step 2: Run Adversarial Tests (Test Execution · UC-1)
1. Click **"Test Execution"** (`UC-1`) in the left sidebar.
2. Select one or more MITRE techniques from the grid (e.g. `T1059.001 - PowerShell`, `T1003.001 - LSASS Memory`).
3. Choose your execution **Variant**:
   - `Base Standard Payload`: Tests basic unevasive execution.
   - `VAR-1` to `VAR-4`: Tests evasive variants (obfuscated cmdlets, reflective loaders, LOLBins).
4. Click the **"Run Tests"** button:
   - The engine detonates the payload and queries the SIEM detection engine.
   - A success banner will confirm whether it ran via the Live Agent Queue or the Direct Orchestrator.
5. In the **Outputs — Execution Log** table:
   - See whether the test generated an **`ALERT`** (detection rule fired) or **`NO ALERT`** (evaded detection).
   - Click on the new run to view its live Sysmon telemetry details.

---

### Step 3: Generate AI Evasion Variants (Variations · UC-2)
1. Click **"Variations"** (`UC-2`) in the sidebar.
2. Choose a **Base Technique** (e.g. `T1059.001 — PowerShell` or `T1003.001 — LSASS Memory`).
3. Either enter a custom evasion goal in **LLM Prompt / Evasion Goals** or click one of the quick **Preset** buttons (e.g. *"Avoid AMSI keyword scanning using split string concatenation"*).
4. Click **"Generate via LLM"**:
   - The AI Variation Engine generates a realistic evasion payload tailored to that technique.
   - The variant appears immediately at the top of the **Variation Repository** table with status `pending_review`.
5. Human-in-the-Loop Review:
   - Click **"Approve"** on the variant.
6. Click the green **"Run Test"** button on your approved variant:
   - This schedules and detonates that specific variant against the SIEM, logging the outcome and updating the coverage matrix!

---

### Step 4: Re-Evaluate Detections & Patch Blind Spots (Re-Evaluation · UC-3)
1. Click **"Re-Evaluation"** (`UC-3`) in the sidebar.
2. Notice the **Outputs — Blind Spots** section showing open gaps (e.g. where `EncodedCommand` or `comsvcs.dll` bypassed rules).
3. Review the **Modified Detection Rules** (e.g. updated Sigma rules) and the **Benign Baseline Activities** (normal login cycles, Windows Update, browser processes).
4. Click **"Run Re-Evaluation"**:
   - The engine tests the updated rules against both the adversarial variations and the benign baselines.
   - Blind spots will transition from <span style="color:#ef4444">**`open`**</span> to <span style="color:#00d4aa">**`patched`**</span>.
   - The **False Positive Evaluation** confirms that the rules remain clean without false alerts on normal traffic.

---

### Step 5: Verify Improvements on the Coverage Matrix (Coverage Matrix · UC-4)
1. Click **"Coverage Matrix"** (`UC-4`) in the sidebar.
2. Observe the full ATT&CK heat matrix:
   - **`✓` (Green)**: SIEM alert fired and successfully detected the technique.
   - **`✗` (Red)**: Adversary evaded detection (blind spot).
   - **`—` (Gray)**: Variant cell not yet evaluated.
3. Review the top KPI cards to see your improved **Overall Coverage %** and fewer **Techniques with Gaps**.
4. Click **"↻ Refresh Matrix"** anytime to sync the latest real-time results from the database.

---

## 📡 API Endpoints Summary

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health status and agent connectivity |
| `GET` | `/api/dashboard/stats` | High-level detection KPIs & metrics |
| `GET` | `/api/techniques` | List MITRE ATT&CK techniques |
| `GET` | `/api/runs` | List test execution logs |
| `POST` | `/api/runs/execute` | Queue and execute test cases |
| `GET` | `/api/variations` | Query variation repository |
| `POST` | `/api/variations/generate` | Generate AI evasion variant |
| `POST` | `/api/variations/{id}/status`| Approve or reject variation |
| `GET` | `/api/blindspots` | Retrieve open & patched blind spots |
| `POST` | `/api/detections/reevaluate` | Re-evaluate rules against baselines |
| `GET` | `/api/coverage/matrix` | Full dynamic coverage matrix |
| `GET` | `/api/agent/poll` | Poll execution queue for agent |
| `POST` | `/api/agent/report` | Report agent execution results |

