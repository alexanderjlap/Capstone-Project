# DetectIQ Test Execution & Report Guide

This guide describes how the **Unit Tests** and **System Tests** are implemented and executed in DetectIQ to generate test reports matching the **Requirements Analysis Document (RAD)** and the **Test Plan**.

---

## 🎯 Architecture of the Test Suite

As outlined in the Test Plan, **Unit Tests** and **System Tests** share the exact same tooling (`pytest`, `pytest-html`) but differ in data scope:

| Dimension | Unit Testing (`tests/unit/`) | System Testing (`tests/system/`) |
|---|---|---|
| **Data Scope** | Mocked data / in-memory DB / isolated functions | Live FastAPI backend & live execution pipeline |
| **Tooling** | `pytest` + `pytest-html` | `pytest` + `pytest-html` |
| **RAD Naming** | `test_req<N>_*` (Req 3 through Req 8) | `test_st<N>_req<N>_*` (ST-1 through ST-7) |
| **Execution Trigger** | Local or CI/CD per commit/PR | Milestones / live lab evaluation |
| **Report Output** | `tests/reports/unit_test_report.html` | `tests/reports/system_test_report.html` |

---

## 📋 Requirement Traceability Matrix

### 1. Unit Tests (`tests/unit/test_requirements_unit.py`)
- **Req 3**: `test_req3_verify_each_detection_rule_maps_to_valid_attack_technique` — Ensures 8 to 12 ATT&CK techniques are registered and mapped to detection rules.
- **Req 4**: `test_req4_verify_detection_latency_is_recorded` — Verifies execution time, Sysmon event count, and latency are recorded.
- **Req 4**: `test_req4_verify_result_is_no_alert_when_evasion_succeeds` — Validates that unpatched evasion variants result in `NO_ALERT`.
- **Req 5**: `test_req5_verify_coverage_equals_detected_divided_by_executed` — Confirms coverage formula equals detected cells divided by total tested cells.
- **Req 6**: `test_req6_verify_variation_response_saved_as_pending` — Confirms new variations are saved as `pending_review`.
- **Req 7**: `test_req7_verify_rejected_variation_is_never_run` — Confirms rejected variations cannot be executed.
- **Req 7**: `test_req7_verify_unapproved_variation_cannot_be_executed` — Enforces approval gating.
- **Req 8**: `test_req8_verify_export_contains_technique_time_result_and_latency` — Verifies log export integrity.

### 2. System Tests (`tests/system/test_system_requirements.py`)
- **ST-1 (Req 1)**: `test_st1_req1_check_system_reachability` — Checks backend API endpoint and agent connectivity health.
- **ST-2 (Req 2)**: `test_st2_req2_verify_telemetry_and_database_persistence` — Tests process execution and multi-event Sysmon logging into SQLite.
- **ST-3 (Req 3)**: `test_st3_req3_run_baseline_test_cases` — Runs baseline technique payload and verifies detection `ALERT`.
- **ST-4 (Req 4)**: `test_st4_req4_automated_suite_execution_through_api` — Automates execution over API with no manual steps.
- **ST-5 (Req 5)**: `test_st5_req5_run_variations_and_verify_coverage` — Runs variations across multiple techniques and updates matrix coverage.
- **ST-6 (Req 6 & 7)**: `test_st6_req6_req7_generate_and_enforce_approval_workflow` — Generates variant, tests `Pending` state and approval transition.
- **ST-7 (Req 8)**: `test_st7_req8_verify_dataset_and_coverage_matrix` — Verifies dataset exports and matrix match the active database.

---

## 🚀 How to Run Tests & Generate Reports

### 1. Prerequisites (Report Generator Plugin)
Install `pytest` and `pytest-html` in the backend virtualenv:
```bash
# Git Bash
./backend/venv/Scripts/python.exe -m pip install pytest pytest-html

# PowerShell
.\backend\venv\Scripts\python.exe -m pip install pytest pytest-html
```

### 2. Running Unit Tests Only
```bash
# Git Bash
./backend/venv/Scripts/python.exe -m pytest tests/unit -v --html=tests/reports/unit_test_report.html --self-contained-html

# PowerShell
.\backend\venv\Scripts\python.exe -m pytest tests/unit -v --html=tests/reports/unit_test_report.html --self-contained-html
```

### 3. Running System Tests (Live Pipeline)
First ensure your backend server is running in another terminal:
```bash
cd backend && ./venv/Scripts/uvicorn.exe main:app --reload --port 8000
```

Then run the system tests:
```bash
# Git Bash
./backend/venv/Scripts/python.exe -m pytest tests/system -v --html=tests/reports/system_test_report.html --self-contained-html

# PowerShell
.\backend\venv\Scripts\python.exe -m pytest tests/system -v --html=tests/reports/system_test_report.html --self-contained-html
```

### 4. One-Click Runner Scripts
You can also run both suites and generate all reports automatically:

**PowerShell:**
```powershell
.\tests\run_tests.ps1 all
```

**Git Bash:**
```bash
./tests/run_tests.sh all
```

Both HTML reports will be generated in `tests/reports/`:
- `tests/reports/unit_test_report.html`
- `tests/reports/system_test_report.html`

Opening either HTML file in your browser provides a visual, professorial report showing passes/fails, execution timings, and the requirement IDs tagged to each test.

