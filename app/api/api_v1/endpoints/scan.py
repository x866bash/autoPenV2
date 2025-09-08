from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional
import uuid
import asyncio
from datetime import datetime

from app.services.scanner import SecurityScanner
from app.services.tools import run_hydra_bruteforce

router = APIRouter()

# In-memory storage for scan results (in production, use a database)
scan_storage = {}

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

@router.post("/scan", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a security scan"""
    scan_id = str(uuid.uuid4())
    
    # Initialize scan record
    scan_storage[scan_id] = {
        "scan_id": scan_id,
        "target": scan_request.target,
        "scan_type": scan_request.scan_type,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "results": {},
        "brute_force_results": []
    }
    
    # Start scan in background
    background_tasks.add_task(run_scan_task, scan_id, scan_request.target, scan_request.scan_type)
    
    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Scan started for {scan_request.target}"
    )

async def run_scan_task(scan_id: str, target: str, scan_type: str):
    """Background task to run the actual scan"""
    try:
        scanner = SecurityScanner()
        
        if scan_type == "full":
            results = await scanner.full_scan(target)
        elif scan_type == "port":
            results = await scanner.port_scan(target)
        elif scan_type == "subdomain":
            results = await scanner.subdomain_scan(target)
        elif scan_type == "vulnerability":
            results = await scanner.vulnerability_scan(target)
        else:
            results = {"error": "Invalid scan type"}
        
        # Update scan record
        scan_storage[scan_id]["results"] = results
        scan_storage[scan_id]["status"] = "completed"
        scan_storage[scan_id]["completed_at"] = datetime.now().isoformat()
        
    except Exception as e:
        scan_storage[scan_id]["status"] = "failed"
        scan_storage[scan_id]["error"] = str(e)
        scan_storage[scan_id]["completed_at"] = datetime.now().isoformat()

@router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get scan status"""
    if scan_id not in scan_storage:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_storage[scan_id]
    return {
        "scan_id": scan_id,
        "target": scan_data["target"],
        "scan_type": scan_data["scan_type"],
        "status": scan_data["status"],
        "started_at": scan_data.get("started_at"),
        "completed_at": scan_data.get("completed_at")
    }

@router.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get scan results"""
    if scan_id not in scan_storage:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_storage[scan_id]

@router.post("/scan/{scan_id}/bruteforce")
async def start_bruteforce(scan_id: str, service: str, port: int, background_tasks: BackgroundTasks):
    """Start brute force attack on a specific service"""
    if scan_id not in scan_storage:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_storage[scan_id]
    target = scan_data["target"]
    
    # Start brute force in background
    background_tasks.add_task(run_bruteforce_task, scan_id, target, service, port)
    
    return {
        "message": f"Brute force attack started on {service}:{port}",
        "target": target,
        "service": service,
        "port": port
    }

async def run_bruteforce_task(scan_id: str, target: str, service: str, port: int):
    """Background task to run brute force attack"""
    try:
        # Run brute force attack
        result = await run_hydra_bruteforce(target, service, port)
        
        # Add result to scan storage
        scan_storage[scan_id]["brute_force_results"].append(result)
        
    except Exception as e:
        # Add failed result
        scan_storage[scan_id]["brute_force_results"].append({
            "service": service,
            "port": port,
            "target": target,
            "status": "failed",
            "error": str(e),
            "credentials_found": [],
            "count": 0
        })

@router.get("/scans")
async def get_all_scans():
    """Get all scans"""
    scans = []
    for scan_id, scan_data in scan_storage.items():
        scans.append({
            "scan_id": scan_id,
            "target": scan_data["target"],
            "scan_type": scan_data["scan_type"],
            "status": scan_data["status"],
            "started_at": scan_data.get("started_at"),
            "completed_at": scan_data.get("completed_at")
        })
    
    return {"scans": scans}

@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan"""
    if scan_id not in scan_storage:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    del scan_storage[scan_id]
    return {"message": "Scan deleted successfully"}

@router.get("/scan/{scan_id}/export/{format}")
async def export_scan_results(scan_id: str, format: str):
    """Export scan results in different formats"""
    if scan_id not in scan_storage:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_storage[scan_id]
    
    if format == "json":
        return scan_data
    elif format == "txt":
        # Generate text report
        report = f"Scan Report for {scan_data['target']}\n"
        report += f"Status: {scan_data['status']}\n"
        report += f"Started: {scan_data.get('started_at', 'N/A')}\n"
        report += f"Completed: {scan_data.get('completed_at', 'N/A')}\n\n"
        
        # Add results
        if scan_data.get('results'):
            report += "Results:\n"
            for key, value in scan_data['results'].items():
                report += f"- {key}: {value}\n"
        
        return {"content": report, "filename": f"scan_report_{scan_id}.txt"}
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")
