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
- **Python 3.10+** (with virtual environment)
- **Node.js 18+** & npm

### 2. Start the Backend API
```powershell
cd backend
.\venv\Scripts\uvicorn.exe main:app --reload --port 8000
```
*The FastAPI backend will automatically initialize and seed the SQLite database (`backend/detectiq.db`) with MITRE techniques, historical runs, variations, and Sigma rules.*
*Interactive API docs are available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).*

### 3. Start the Frontend Application
In a separate terminal:
```powershell
cd frontend
npm run dev
```
*Open [http://localhost:5173](http://localhost:5173) in your browser.*

### 4. (Optional) Run the Windows Execution Agent
To connect the live external execution agent:
```powershell
cd agent
.\venv\Scripts\python.exe ExecutionAgent.py
```
*Note: If the agent is not running, the backend's built-in orchestration engine automatically executes and evaluates test cases so the UI is always fully interactive.*

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
