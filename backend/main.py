from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import List

from TestOrchestrator import TestOrchestrator
from VariationEngine import VariationEngine
from SIEMPoller import SIEMPoller
from TestCase import TestCase

app = FastAPI(title="DetectIQ API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = TestOrchestrator()
variation_engine = VariationEngine()

@app.get("/")
def read_root():
    return {"status": "DetectIQ Backend is Running"}

@app.post("/api/runs/execute")
def execute_test_cases(techniqueIDs: List[str]):
    results = []
    for tech_id in techniqueIDs:
        results.append({"technique": tech_id, "status": "QUEUED"})
    return {"message": "Execution started", "queue": results}

@app.post("/api/variations/generate")
def generate_variations(baseTechnique: str, method: str, prompt: str):
    return {"message": f"Generated variations for {baseTechnique} via {method}"}

@app.get("/api/coverage/matrix")
def get_coverage_matrix():
    return orchestrator.compileCoverageMatrix()