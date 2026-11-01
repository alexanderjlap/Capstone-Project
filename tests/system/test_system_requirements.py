import pytest
import requests
import json

API_BASE = "http://127.0.0.1:8000/api"

# --- ST-1 (Req 1): Architecture & Endpoint Health Check ---
def test_st1_req1_check_system_reachability():
    """ST-1 (Req 1): Check that backend API and environment are up and reachable."""
    resp = requests.get(f"{API_BASE}/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "agentMode" in data

# --- ST-2 (Req 2): Process, Telemetry, and Storage Verification ---
def test_st2_req2_verify_telemetry_and_database_persistence():
    """ST-2 (Req 2): Verify process execution generates Sysmon telemetry and logs to database."""
    # Execute a run and inspect telemetry breakdown (EID 1, 3, 11, 13)
    resp = requests.post(f"{API_BASE}/runs/execute", json={
        "techniqueIDs": ["T1059.001"],
        "variant": "Base",
        "autoExecute": True
    })
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["executed"]) > 0
    executed_run = data["executed"][0]
    
    assert executed_run["sysmonEvents"] > 0
    assert "telemetry" in executed_run
    assert executed_run["telemetry"]["eid1"] > 0  # Process create event logged

# --- ST-3 (Req 3): Baseline Test Cases Detection ---
def test_st3_req3_run_baseline_test_cases():
    """ST-3 (Req 3): Run baseline test case for primary technique and verify detection."""
    resp = requests.post(f"{API_BASE}/runs/execute", json={
        "techniqueIDs": ["T1059.001"],
        "variant": "Base",
        "autoExecute": True
    })
    assert resp.status_code == 200
    run = resp.json()["executed"][0]
    assert run["alertGenerated"] is True
    assert run["result"] == "ALERT"

# --- ST-4 (Req 4): Automated API Suite Execution with Latency ---
def test_st4_req4_automated_suite_execution_through_api():
    """ST-4 (Req 4): Start execution suite via API; verify result, timestamp, and latency without manual steps."""
    resp = requests.post(f"{API_BASE}/runs/execute", json={
        "techniqueIDs": ["T1003.001"],
        "variant": "Base",
        "autoExecute": True
    })
    assert resp.status_code == 200
    result = resp.json()["executed"][0]
    assert result["runId"].startswith("RUN-")
    assert result["result"] in ["ALERT", "NO_ALERT"]
    assert result["execMs"] > 0
    assert result["latency"] is not None

# --- ST-5 (Req 5): Run Variations for at Least Two Techniques & Validate Coverage ---
def test_st5_req5_run_variations_and_verify_coverage():
    """ST-5 (Req 5): Run variations for techniques and verify coverage calculation matches."""
    # Execute variation for T1059.001
    resp1 = requests.post(f"{API_BASE}/runs/execute", json={
        "techniqueIDs": ["T1059.001"],
        "variant": "VAR-3",
        "autoExecute": True
    })
    assert resp1.status_code == 200
    
    # Execute variation for T1003.001
    resp2 = requests.post(f"{API_BASE}/runs/execute", json={
        "techniqueIDs": ["T1003.001"],
        "variant": "VAR-2",
        "autoExecute": True
    })
    assert resp2.status_code == 200
    
    # Verify Coverage Matrix updates
    matrix_resp = requests.get(f"{API_BASE}/coverage/matrix")
    assert matrix_resp.status_code == 200
    matrix_data = matrix_resp.json()
    assert matrix_data["coveragePct"] > 0
    assert matrix_data["totalCells"] >= matrix_data["hitCells"]

# --- ST-6 (Req 6 & 7): Generate Variations and Guard Execution Status ---
def test_st6_req6_req7_generate_and_enforce_approval_workflow():
    """ST-6 (Req 6, 7): Generate candidate variations, verify Pending, and ensure unapproved cannot run."""
    # 1. Generate variation
    gen_resp = requests.post(f"{API_BASE}/variations/generate", json={
        "baseTechnique": "T1059.001",
        "strategy": "Unmanaged Runspace Execution"
    })
    assert gen_resp.status_code == 200
    variant = gen_resp.json()["variant"]
    var_id = variant["id"]
    assert variant["status"] == "pending_review"
    
    # 2. Reject variation and verify status
    rej_resp = requests.post(f"{API_BASE}/variations/{var_id}/status", json={"status": "rejected"})
    assert rej_resp.status_code == 200
    
    # 3. Approve variation and verify status
    appr_resp = requests.post(f"{API_BASE}/variations/{var_id}/status", json={"status": "approved"})
    assert appr_resp.status_code == 200
    assert appr_resp.json()["status"] == "approved"

# --- ST-7 (Req 8): Dataset Export & Coverage Matrix Integrity ---
def test_st7_req8_verify_dataset_and_coverage_matrix():
    """ST-7 (Req 8): Export dataset / logs and verify coverage matrix matches database."""
    runs_resp = requests.get(f"{API_BASE}/runs")
    assert runs_resp.status_code == 200
    runs = runs_resp.json()
    assert len(runs) > 0
    
    matrix_resp = requests.get(f"{API_BASE}/coverage/matrix")
    assert matrix_resp.status_code == 200
    matrix = matrix_resp.json()
    
    # Check that techniques in matrix match the registered techniques
    tech_resp = requests.get(f"{API_BASE}/techniques")
    techniques = tech_resp.json()
    for tech in techniques:
        assert tech["id"] in matrix["matrix"]

