from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from enum import Enum

class ScanType(str, Enum):
    full = "full"
    port = "port"
    subdomain = "subdomain"
    vulnerability = "vulnerability"

class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"

class ScanRequest(BaseModel):
    target: str
    scan_type: ScanType = ScanType.full

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class ScanResult(BaseModel):
    scan_id: str
    target: str
    scan_type: str
    status: ScanStatus
    progress: int = 0
    results: Dict[str, Any] = {}
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None

class BruteForceRequest(BaseModel):
    service: str = "ssh"
    port: int = 22

class BruteForceResult(BaseModel):
    tool: str
    target: str
    service: str
    port: int
    status: str
    credentials_found: List[Dict[str, str]] = []
    error: Optional[str] = None
    execution_time: Optional[float] = None
