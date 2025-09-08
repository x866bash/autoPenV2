from fastapi import APIRouter, HTTPException, BackgroundTasks
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.scanner import SecurityScanner
from app.services.tools import run_hydra_bruteforce
import asyncio
import uuid
from typing import Dict, Any

router = APIRouter()

# Store scan results in memory (in production, use a database)
scan_results: Dict[str, Dict[str, Any]] = {}

@router.post("/scan", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a security scan on the target domain"""
    scan_id = str(uuid.uuid4())
    
    # Initialize scan result
    scan_results[scan_id] = {
        "status": "running",
        "target": scan_request.target,
        "scan_type": scan_request.scan_type,
        "results": {},
        "open_ports": [],
        "brute_force_results": []
    }
    
    # Start scan in background
    background_tasks.add_task(run_scan, scan_id, scan_request.target, scan_request.scan_type)
    
    return ScanResponse(scan_id=scan_id, status="started", message="Scan initiated successfully")

async def run_scan(scan_id: str, target: str, scan_type: str):
    """Run the actual security scan"""
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
        
        # Extract open ports for brute force
        open_ports = []
        if "nmap" in results:
            nmap_output = results["nmap"]
            if "open" in nmap_output.lower():
                # Parse open ports from nmap output
                lines = nmap_output.split('\n')
                for line in lines:
                    if "/tcp" in line and "open" in line:
                        port = line.split('/')[0].strip()
                        service = line.split()[-1] if len(line.split()) > 2 else "unknown"
                        try:
                            port_num = int(port)
                            open_ports.append({"port": port_num, "service": service})
                        except ValueError:
                            continue
        
        scan_results[scan_id].update({
            "status": "completed",
            "results": results,
            "open_ports": open_ports
        })
        
    except Exception as e:
        scan_results[scan_id].update({
            "status": "failed",
            "error": str(e)
        })

@router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get the status of a scan"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    result = scan_results[scan_id]
    return {
        "scan_id": scan_id,
        "status": result["status"],
        "target": result["target"],
        "scan_type": result["scan_type"]
    }

@router.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get the results of a completed scan"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_results[scan_id]

@router.post("/scan/{scan_id}/bruteforce")
async def start_bruteforce(scan_id: str, background_tasks: BackgroundTasks, service: str = "ssh", port: int = 22):
    """Start brute force attack on a specific service"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_results[scan_id]
    target = scan_data["target"]
    
    # Start brute force in background
    background_tasks.add_task(run_bruteforce, scan_id, target, service, port)
    
    return {"message": f"Brute force attack started on {service}:{port}", "scan_id": scan_id}

async def run_bruteforce(scan_id: str, target: str, service: str, port: int):
    """Run brute force attack"""
    try:
        # Update status
        scan_results[scan_id]["brute_force_status"] = "running"
        
        # Run Hydra brute force
        result = await run_hydra_bruteforce(target, service, port)
        
        # Store results
        if scan_id in scan_results:
            if "brute_force_results" not in scan_results[scan_id]:
                scan_results[scan_id]["brute_force_results"] = []
            
            scan_results[scan_id]["brute_force_results"].append({
                "service": service,
                "port": port,
                "result": result,
                "status": "completed"
            })
            scan_results[scan_id]["brute_force_status"] = "completed"
        
    except Exception as e:
        if scan_id in scan_results:
            scan_results[scan_id]["brute_force_status"] = "failed"
            scan_results[scan_id]["brute_force_error"] = str(e)

@router.get("/scan/{scan_id}/bruteforce")
async def get_bruteforce_results(scan_id: str):
    """Get brute force results"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_results[scan_id]
    return {
        "scan_id": scan_id,
        "brute_force_status": scan_data.get("brute_force_status", "not_started"),
        "brute_force_results": scan_data.get("brute_force_results", []),
        "brute_force_error": scan_data.get("brute_force_error")
    }

@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan and its results"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    del scan_results[scan_id]
    return {"message": "Scan deleted successfully"}
