from typing import List
from TestCase import TestCase

class TestOrchestrator:
    def __init__(self):
        self.dbConnection = None 
        self.activeTestQueue: List[TestCase] = []

    def initializeTestRun(self, techniqueID: str) -> bool:
        pass

    def scheduleExecution(self, test: TestCase) -> None:
        pass

    def compileCoverageMatrix(self) -> dict: 
        return {"status": "Coverage matrix will render here"}