from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime
import uuid

class TestCase(BaseModel):
    testID: str = Field(default_factory=lambda: str(uuid.uuid4()))
    runId: Optional[str] = None
    mitreTechnique: str
    variant: str = "Base"
    variantId: Optional[str] = None
    payloadExecutionString: str
    isAIVariation: bool = False
    executionTimestamp: Optional[datetime] = None
    alertGenerated: Optional[bool] = None
    detectionLatencySeconds: Optional[float] = None
    
    sysmonEvents: Optional[int] = 0
    eid1_count: Optional[int] = 0
    eid3_count: Optional[int] = 0
    eid11_count: Optional[int] = 0
    eid13_count: Optional[int] = 0
    executionErrors: Optional[str] = None
    commandLine: Optional[str] = None
    parentProcess: Optional[str] = "cmd.exe"

    def updateDetectionStatus(self, status: bool, latency: float, sysmon_count: int = 0, errors: str = None) -> None:
        self.alertGenerated = status
        self.detectionLatencySeconds = latency
        self.sysmonEvents = sysmon_count
        self.executionErrors = errors
