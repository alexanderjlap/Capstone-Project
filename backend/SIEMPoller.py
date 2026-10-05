class SIEMPoller:
    def __init__(self):
        self.siemQueryEndpoint = ""
        self.maxPollingTimeout = 300

    def queryForAlert(self, techniqueID: str, executionTime) -> bool:
        return False

    def calculateLatency(self, executionTime, alertTime) -> float:
        return 0.0