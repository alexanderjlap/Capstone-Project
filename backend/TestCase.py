from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
import uuid

class TestCase(BaseModel):
    testID: str = Field(default_factory=lambda: str(uuid.uuid4()))
    mitreTechnique: str
    payloadExecutionString: str
    isAIVariation: bool = False
    executionTimestamp: Optional[datetime] = None
    alertGenerated: Optional[bool] = None
    detectionLatencySeconds: Optional[float] = None

    def updateDetectionStatus(self, status: bool, latency: float) -> None:
        self.alertGenerated = status
        self.detectionLatencySeconds = latency