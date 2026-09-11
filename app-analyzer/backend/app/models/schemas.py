from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ProductionGate(str, Enum):
    READY = "READY"
    NEEDS_HARDENING = "NEEDS_HARDENING"
    BLOCKED = "BLOCKED_CRITICAL_RISK"

class SecurityFinding(BaseModel):
    severity: SeverityLevel
    category: str
    title: str
    description: str
    cwe: str
    remediation: str
    evidence: Optional[str] = None

class AnalysisSummary(BaseModel):
    hackabilityScore: float = Field(..., ge=0.0, le=10.0, description="1.0 is fortified, 10.0 is trivially exploitable")
    productionGate: ProductionGate
    criticalCount: int = 0
    highCount: int = 0
    mediumCount: int = 0
    lowCount: int = 0
    totalFindings: int = 0
    executiveSummary: str

class AnalysisReportResponse(BaseModel):
    reportId: str
    status: str
    fileName: str
    fileType: str
    fileSizeBytes: int
    hashes: Dict[str, str]
    summary: AnalysisSummary
    securityFindings: List[SecurityFinding]
    improvements: List[str]
    hardeningPrompt: str
    staticDetails: Dict[str, Any]
    createdAt: str

class UploadResponse(BaseModel):
    reportId: str
    fileName: str
    fileType: str
    status: str
    message: str
