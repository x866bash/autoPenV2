from fastapi import APIRouter
from app.api.api_v1.endpoints import scan

api_router = APIRouter()
api_router.include_router(scan.router, tags=["scanning"])

# Add a scans endpoint for listing all scans
@api_router.get("/scans")
async def list_all_scans():
    """List all scans - delegated to scan module"""
    from app.api.api_v1.endpoints.scan import scan_results
    
    return {
        "scans": [
            {
                "scan_id": scan_id,
                "target": data["target"],
                "scan_type": data["scan_type"],
                "status": data["status"],
                "progress": data.get("progress", 0)
            }
            for scan_id, data in scan_results.items()
        ]
    }
