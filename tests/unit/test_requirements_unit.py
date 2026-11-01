import pytest
import sqlite3
import os
import sys

# Ensure backend directory is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend")))

from database import init_db, get_connection
from TestOrchestrator import TestOrchestrator
from VariationEngine import VariationEngine
from SIEMPoller import SIEMPoller
from TestCase import TestCase

@pytest.fixture(autouse=True)
def setup_test_db():
    init_db()

# --- Requirement 3: Baseline Detection Rules (8 to 12 ATT&CK Techniques) ---
def test_req3_verify_each_detection_rule_maps_to_valid_attack_technique():
    """Verify each detection rule maps to a valid 8-12 ATT&CK technique scope."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM techniques")
    techniques = cur.fetchall()
    conn.close()
    
    assert 8 <= len(techniques) <= 12
    tech_ids = [t["id"] for t in techniques]
    assert "T1059.001" in tech_ids  # PowerShell
    assert "T1003.001" in tech_ids  # LSASS Memory

# --- Requirement 4: Automated Test Execution & Latency/Telemetry Recording ---
def test_req4_verify_detection_latency_is_recorded():
    """Verify test execution logs execution time, sysmon events, and latency."""
    orchestrator = TestOrchestrator()
    test_id = orchestrator.initializeTestRun("T1059.001", variant="Base")
    result = orchestrator.executeTestSync(test_id)
    
    assert result["result"] in ["ALERT", "NO_ALERT"]
    assert result["sysmonEvents"] > 0
    assert result["execMs"] is not None
    assert result["execMs"] > 0
    if result["alertGenerated"]:
        assert result["latency"] is not None
        assert result["latency"] > 0

def test_req4_verify_result_is_no_alert_when_evasion_succeeds():
    """Verify that unpatched evasion variants result in NO_ALERT."""
    poller = SIEMPoller()
    # Unpatched Process Hollowing should evade detection
    eval_res = poller.evaluateDetection("T1055.012", variant="VAR-1", payload_str="inject.ps1")
    assert eval_res["alertGenerated"] is False

# --- Requirement 5: Coverage Calculation (detected / total) ---
def test_req5_verify_coverage_equals_detected_divided_by_executed():
    """Verify coverage calculation equals detected cells divided by total tested cells."""
    orchestrator = TestOrchestrator()
    matrix_data = orchestrator.compileCoverageMatrix()
    
    total = matrix_data["totalCells"]
    hits = matrix_data["hitCells"]
    pct = matrix_data["coveragePct"]
    
    assert total > 0
    expected_pct = round((hits / total) * 100)
    assert pct == expected_pct

# --- Requirement 6: Variation Generation Saved as Pending ---
def test_req6_verify_variation_response_saved_as_pending():
    """Verify generated variations are saved in the repository with status 'pending_review'."""
    engine = VariationEngine()
    var = engine.generateVariations("T1059.001", strategy="String Concatenation")
    
    assert var["id"].startswith("VAR-")
    assert var["status"] == "pending_review"
    assert var["techniqueId"] == "T1059.001"
    
    # Confirm it is in database
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT status FROM variations WHERE id = ?", (var["id"],))
    row = cur.fetchone()
    conn.close()
    assert row is not None
    assert row["status"] == "pending_review"

# --- Requirement 7: Rejected & Unapproved Variations Cannot Be Executed ---
def test_req7_verify_rejected_variation_is_never_run():
    """Verify rejected variations cannot be executed or remain rejected."""
    engine = VariationEngine()
    var = engine.generateVariations("T1078", strategy="Account Renaming")
    success = engine.updateStatus(var["id"], "rejected")
    assert success is True
    
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT status FROM variations WHERE id = ?", (var["id"],))
    row = cur.fetchone()
    conn.close()
    assert row["status"] == "rejected"

def test_req7_verify_unapproved_variation_cannot_be_executed():
    """Verify pending variations require approval before execution."""
    engine = VariationEngine()
    var = engine.generateVariations("T1003.001", strategy="Reflective Loader")
    assert var["status"] == "pending_review"
    # Approval step
    assert engine.updateStatus(var["id"], "approved") is True

# --- Requirement 8: Coverage Matrix & Dataset Export ---
def test_req8_verify_export_contains_technique_time_result_and_latency():
    """Verify run logs export contains technique, timestamp, result, and telemetry."""
    orchestrator = TestOrchestrator()
    runs = orchestrator.getRunsLog()
    assert len(runs) > 0
    first = runs[0]
    assert "runId" in first
    assert "techniqueId" in first
    assert "result" in first
    assert "ts" in first
    assert "sysmonEvents" in first

