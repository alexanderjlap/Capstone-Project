from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Optional, Any
from pydantic import BaseModel
import datetime

from database import init_db, get_connection
from TestOrchestrator import TestOrchestrator
from VariationEngine import VariationEngine
from SIEMPoller import SIEMPoller

# Initialize SQLite database schema and seed data
init_db()

app = FastAPI(
    title="DetectIQ API",
    description="Backend API for DetectIQ Detection Robustness Framework",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = TestOrchestrator()
variation_engine = VariationEngine()
siem_poller = SIEMPoller()

# --- Request / Response Models ---

from typing import List, Dict, Optional, Any, Union

class ExecutePayload(BaseModel):
    techniqueIDs: List[str]
    variant: Optional[str] = "Base"
    variantId: Optional[str] = None
    customPayload: Optional[str] = None
    autoExecute: Optional[bool] = True

class VariationGeneratePayload(BaseModel):
    baseTechnique: str
    strategy: Optional[str] = ""
    prompt: Optional[str] = ""
    method: Optional[str] = "Rule-Based"

class VariationStatusPayload(BaseModel):
    status: str # "approved" | "rejected" | "pending_review"

class ReportPayload(BaseModel):
    testID: str
    success: bool
    sysmonEvents: int = 0
    execMs: Optional[int] = None
    telemetry: Optional[Dict[str, int]] = None

# --- Health & Dashboard Endpoints ---

@app.get("/api/health")
def get_health():
    agent_active = False
    if orchestrator.agent_last_seen:
        diff = (datetime.datetime.now() - orchestrator.agent_last_seen).total_seconds()
        agent_active = diff < 30

    return {
        "status": "healthy",
        "service": "DetectIQ API",
        "agentConnected": agent_active,
        "agentMode": "Live Execution Agent" if agent_active else "Built-in Orchestration Engine",
        "timestamp": datetime.datetime.now().isoformat()
    }

@app.get("/api/dashboard/stats")
def get_dashboard_stats():
    matrix_info = orchestrator.compileCoverageMatrix()
    blind_spots = orchestrator.getBlindSpots()
    open_blind_spots = sum(1 for b in blind_spots if b["status"] == "open")
    variations = variation_engine.listVariations()
    variants_count = len(variations)
    runs = orchestrator.getRunsLog()

    agent_active = False
    if orchestrator.agent_last_seen:
        diff = (datetime.datetime.now() - orchestrator.agent_last_seen).total_seconds()
        agent_active = diff < 30

    return {
        "coveragePct": matrix_info["coveragePct"],
        "totalCells": matrix_info["totalCells"],
        "hitCells": matrix_info["hitCells"],
        "techniquesCount": len(matrix_info["matrix"]),
        "openBlindSpots": open_blind_spots,
        "variantsGenerated": variants_count,
        "aiVariantsGenerated": variants_count,
        "agentConnected": agent_active,
        "recentRuns": runs[:10]
    }

# --- MITRE Techniques ---

@app.get("/api/techniques")
def get_techniques():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name, tactic, severity, description, default_payload FROM techniques")
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "tactic": r["tactic"],
            "severity": r["severity"],
            "description": r["description"],
            "defaultPayload": r["default_payload"]
        }
        for r in rows
    ]

# --- Test Execution Runs ---

@app.get("/api/runs")
def get_runs():
    return orchestrator.getRunsLog()

@app.get("/api/runs/{run_id}")
def get_run_detail(run_id: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM runs_log WHERE run_id = ?", (run_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Run not found")
    return dict(row)

@app.post("/api/runs/execute")
def execute_test_cases(payload: Union[ExecutePayload, List[str]]):
    technique_ids = []
    variant = "Base"
    variant_id = None
    custom_payload = None
    auto_execute = True

    if isinstance(payload, list):
        technique_ids = payload
    elif isinstance(payload, ExecutePayload):
        technique_ids = payload.techniqueIDs
        variant = payload.variant or "Base"
        variant_id = payload.variantId
        custom_payload = payload.customPayload
        auto_execute = payload.autoExecute if payload.autoExecute is not None else True

    results = []
    executed_results = []
    for tech_id in technique_ids:
        test_id = orchestrator.initializeTestRun(
            techniqueID=tech_id,
            variant=variant,
            variantID=variant_id,
            custom_payload=custom_payload
        )
        results.append({"technique": tech_id, "testID": test_id, "status": "QUEUED"})

        # If autoExecute is true and agent hasn't polled within 15 seconds,
        # execute synchronously so user gets real immediate data feedback
        agent_is_active = False
        if orchestrator.agent_last_seen:
            agent_is_active = (datetime.datetime.now() - orchestrator.agent_last_seen).total_seconds() < 15

        if auto_execute and not agent_is_active:
            exec_res = orchestrator.executeTestSync(test_id)
            executed_results.append(exec_res)

    return {
        "message": "Execution processed",
        "queue": results,
        "executed": executed_results,
        "mode": "Live Agent Queue" if (orchestrator.agent_last_seen and (datetime.datetime.now() - orchestrator.agent_last_seen).total_seconds() < 15) else "Direct Orchestrator Execution"
    }

# --- Variations Endpoints ---

@app.get("/api/variations")
def get_variations(techniqueId: Optional[str] = None):
    return variation_engine.listVariations(techniqueId)

@app.post("/api/variations/generate")
def generate_variations(payload: VariationGeneratePayload):
    strategy_param = payload.strategy or payload.prompt or ""
    variant = variation_engine.generateVariations(payload.baseTechnique, strategy=strategy_param, method=payload.method)
    return {"message": "Success", "variant": variant}

@app.post("/api/variations/{variation_id}/status")
def update_variation_status(variation_id: str, payload: VariationStatusPayload):
    success = variation_engine.updateStatus(variation_id, payload.status)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to update variation status")
    return {"message": "Status updated", "id": variation_id, "status": payload.status}

# --- Blind Spots & Re-evaluation ---

@app.get("/api/blindspots")
def get_blind_spots():
    return orchestrator.getBlindSpots()

@app.get("/api/detections/rules")
def get_detection_rules():
    return orchestrator.getDetectionRules()

@app.post("/api/detections/reevaluate")
def reevaluate_detections():
    result = orchestrator.runReEvaluation()
    return result

# --- Coverage Matrix ---

@app.get("/api/coverage/matrix")
def get_coverage_matrix():
    return orchestrator.compileCoverageMatrix()

# --- Agent Endpoints ---

@app.get("/api/agent/poll")
def poll_for_tasks():
    return orchestrator.getNextTask()

@app.post("/api/agent/report")
def report_task(payload: ReportPayload):
    orchestrator.logExecutionResult(
        testID=payload.testID,
        success=payload.success,
        sysmon_count=payload.sysmonEvents,
        exec_ms=payload.execMs,
        telemetry=payload.telemetry
    )
    print(f"[Agent Report] Test {payload.testID} complete. Sysmon Events: {payload.sysmonEvents}")
    return {"status": "acknowledged"}
