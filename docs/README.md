# DetectIQ — Project Documentation & Submission Artifacts

**Senior Capstone Project**  
**Authors:** Nathan Amend & Alex Lap  
**Topic:** Detection Robustness Framework (MITRE ATT&CK, Evasion Variations, SIEM/EDR Re-Evaluation)

---

## 📚 Deliverables & Documentation Index

This directory serves as the documentation repository for DetectIQ deliverables:

| Document / Asset | Description | Location |
|---|---|---|
| **System Architecture** | Component overview (FastAPI, React 19, SQLite, Windows Execution Agent) | [System Architecture](#system-architecture) & [`README.md`](../README.md#system-architecture) |
| **Requirements Traceability Matrix** | Formal mapping of RAD requirements (Req 1 – Req 8) to implementation and tests | [`tests/README.md`](../tests/README.md#requirement-traceability-matrix) |
| **Unit Test Report** | Automated HTML test report with execution timings and requirement verification | [`tests/reports/unit_test_report.html`](../tests/reports/unit_test_report.html) |
| **System Test Report** | End-to-end integration test report over live API and telemetry pipeline | [`tests/reports/system_test_report.html`](../tests/reports/system_test_report.html) |
| **Interactive API Documentation** | Swagger / OpenAPI 3.0 specification | Live at `http://127.0.0.1:8000/docs` when backend is running |

---

## 🏛️ System Architecture

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

### Component Roles:
1. **Frontend (`frontend/`)**: React 19 single-page dashboard with Tailwind CSS styling, providing real-time telemetry inspection, test execution controls, human-in-the-loop variation approval (Req 7), and dynamic coverage matrix heatmaps (Req 5).
2. **Backend (`backend/`)**: FastAPI application exposing RESTful endpoints, managing database transactions, coordinating test queues, and evaluating Sigma detection rules against simulated benign/adversarial payloads.
3. **Execution Agent (`agent/`)**: Python agent designed to poll the queue from a target Windows environment (e.g., `lab-dc01`), safely detonate adversarial diagnostic payloads, and report structured Sysmon telemetry back to the backend.
4. **Test Suite (`tests/`)**: Automated verification pipeline generating standalone HTML reports for professor and evaluator review.

---

## 🎯 Use Case Alignment

- **UC-1 (Test Execution & Telemetry Recording)**: Detonates baseline payloads across 10 MITRE techniques; records EID 1 (Process), EID 3 (Network), EID 11 (File), and EID 13 (Registry) telemetry alongside detection latency.
- **UC-2 (Adversarial Variation Generation & Approval)**: Generates rule-based obfuscation and LOLBin evasions; enforces human-in-the-loop review (`pending_review` $\rightarrow$ `approved` / `rejected`).
- **UC-3 (Continuous Detection Re-Evaluation)**: Tests modified Sigma rules against variations and benign baselines to eliminate blind spots while preventing false positives.
- **UC-4 (Dynamic Coverage Matrix)**: Aggregates real-time detection pass/fail status across all techniques and variants to compute the overall coverage percentage.
