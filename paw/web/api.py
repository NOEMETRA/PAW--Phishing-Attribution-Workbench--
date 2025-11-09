"""
PAW Web API
FastAPI backend for modern GUI
"""

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional, Dict
import os
import json
import asyncio
from datetime import datetime
from pathlib import Path

# Import PAW core
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

app = FastAPI(
    title="PAW - Phishing Attribution Workbench",
    description="Modern web interface for phishing analysis",
    version="2.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Paths
CASES_DIR = Path("cases")
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# Analysis queue
analysis_queue = {}


class AnalysisRequest(BaseModel):
    file_path: str
    profile: str = "default"
    options: Dict = {}


class CaseQuery(BaseModel):
    query_type: str  # "ip", "domain", "asn"
    value: str


@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "name": "PAW API",
        "version": "2.0.0",
        "status": "operational",
        "endpoints": {
            "upload": "/api/upload",
            "analyze": "/api/analyze",
            "cases": "/api/cases",
            "case_detail": "/api/cases/{case_id}",
            "statistics": "/api/statistics"
        }
    }


@app.post("/api/upload")
async def upload_email(file: UploadFile = File(...)):
    """Upload email file for analysis"""
    try:
        # Validate file type
        if not file.filename.endswith(('.eml', '.msg')):
            raise HTTPException(400, "Only .eml and .msg files supported")

        # Save file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp}_{file.filename}"
        file_path = UPLOAD_DIR / safe_filename

        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)

        return {
            "status": "success",
            "filename": safe_filename,
            "path": str(file_path),
            "size": len(content)
        }

    except Exception as e:
        raise HTTPException(500, f"Upload failed: {str(e)}")


@app.post("/api/analyze")
async def analyze_email(request: AnalysisRequest, background_tasks: BackgroundTasks):
    """Start email analysis"""
    try:
        file_path = Path(request.file_path)
        if not file_path.exists():
            raise HTTPException(404, "File not found")

        # Generate analysis ID
        analysis_id = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Add to queue
        analysis_queue[analysis_id] = {
            "status": "queued",
            "file": str(file_path),
            "started_at": datetime.now().isoformat(),
            "progress": 0
        }

        # Start background analysis
        background_tasks.add_task(run_analysis, analysis_id, file_path, request.profile, request.options)

        return {
            "status": "queued",
            "analysis_id": analysis_id,
            "message": "Analysis started"
        }

    except Exception as e:
        raise HTTPException(500, f"Analysis failed: {str(e)}")


async def run_analysis(analysis_id: str, file_path: Path, profile: str, options: Dict):
    """Run PAW analysis in background"""
    import logging
    import concurrent.futures
    logger = logging.getLogger(__name__)

    try:
        analysis_queue[analysis_id]["status"] = "running"
        analysis_queue[analysis_id]["progress"] = 10

        # Import PAW trace module
        from paw.core import trace

        # Determine analysis mode based on profile
        mode_options = {
            "quick": {"deobfuscate": True, "threat_intel": False, "detonate": False},
            "full": {"deobfuscate": True, "threat_intel": True, "detonate": True},
            "forensic": {"deobfuscate": True, "threat_intel": True, "detonate": True, "sign": True, "rekor": True}
        }

        analysis_options = mode_options.get(profile, mode_options["full"])
        # Merge with custom options
        analysis_options.update(options)

        # Update progress
        analysis_queue[analysis_id]["progress"] = 30

        # Run actual PAW analysis (synchronous operation)
        # Execute in thread pool to avoid blocking event loop
        loop = asyncio.get_event_loop()

        def run_sync_analysis():
            return trace.trace_sources(
                str(file_path),
                deobfuscate=analysis_options.get("deobfuscate", True),
                threat_intel=analysis_options.get("threat_intel", True),
                detonate=analysis_options.get("detonate", False),
                sign=analysis_options.get("sign", False),
                rekor=analysis_options.get("rekor", False)
            )

        # Run in executor to prevent blocking
        with concurrent.futures.ThreadPoolExecutor() as executor:
            case_id = await loop.run_in_executor(executor, run_sync_analysis)

        analysis_queue[analysis_id]["progress"] = 100
        analysis_queue[analysis_id]["status"] = "completed"
        analysis_queue[analysis_id]["completed_at"] = datetime.now().isoformat()
        analysis_queue[analysis_id]["case_id"] = case_id

        logger.info(f"Analysis {analysis_id} completed successfully: {case_id}")

    except Exception as e:
        logger.error(f"Analysis {analysis_id} failed: {e}", exc_info=True)
        analysis_queue[analysis_id]["status"] = "failed"
        analysis_queue[analysis_id]["error"] = str(e)
        analysis_queue[analysis_id]["completed_at"] = datetime.now().isoformat()


@app.get("/api/analysis/{analysis_id}")
async def get_analysis_status(analysis_id: str):
    """Get analysis status"""
    if analysis_id not in analysis_queue:
        raise HTTPException(404, "Analysis not found")

    return analysis_queue[analysis_id]


@app.get("/api/cases")
async def list_cases(limit: int = 20, offset: int = 0):
    """List all analysis cases"""
    try:
        cases = []

        if not CASES_DIR.exists():
            return {"cases": [], "total": 0}

        # List case directories
        case_dirs = sorted([d for d in CASES_DIR.iterdir() if d.is_dir()],
                          key=lambda x: x.stat().st_mtime,
                          reverse=True)

        for case_dir in case_dirs[offset:offset+limit]:
            manifest_file = case_dir / "manifest.json"
            if manifest_file.exists():
                with open(manifest_file) as f:
                    manifest = json.load(f)
                    cases.append({
                        "case_id": case_dir.name,
                        "created_at": manifest.get("created_at"),
                        "status": "completed",
                        "summary": manifest.get("summary", {})
                    })

        return {
            "cases": cases,
            "total": len(case_dirs),
            "limit": limit,
            "offset": offset
        }

    except Exception as e:
        raise HTTPException(500, f"Failed to list cases: {str(e)}")


@app.get("/api/cases/{case_id}")
async def get_case_detail(case_id: str):
    """Get detailed case information"""
    try:
        case_dir = CASES_DIR / case_id

        if not case_dir.exists():
            raise HTTPException(404, "Case not found")

        # Load all case files
        result = {"case_id": case_id}

        # Manifest
        manifest_file = case_dir / "manifest.json"
        if manifest_file.exists():
            with open(manifest_file) as f:
                result["manifest"] = json.load(f)

        # Score
        score_file = case_dir / "report" / "score.json"
        if score_file.exists():
            with open(score_file) as f:
                result["score"] = json.load(f)

        # Executive report
        exec_file = case_dir / "report" / "executive.md"
        if exec_file.exists():
            with open(exec_file) as f:
                result["executive_report"] = f.read()

        # Technical report
        tech_file = case_dir / "report" / "technical.md"
        if tech_file.exists():
            with open(tech_file) as f:
                result["technical_report"] = f.read()

        # Origin info
        origin_file = case_dir / "origin.json"
        if origin_file.exists():
            with open(origin_file) as f:
                result["origin"] = json.load(f)

        # Auth results
        auth_file = case_dir / "auth.json"
        if auth_file.exists():
            with open(auth_file) as f:
                result["authentication"] = json.load(f)

        # Deobfuscation results
        deob_file = case_dir / "deobfuscation_results.json"
        if deob_file.exists():
            with open(deob_file) as f:
                result["deobfuscation"] = json.load(f)

        # Criminal intelligence (if exists)
        criminal_file = case_dir / "detonation" / "criminal_intelligence.json"
        if criminal_file.exists():
            with open(criminal_file) as f:
                result["criminal_intelligence"] = json.load(f)

        # Attribution matrix
        attr_file = case_dir / "attribution_matrix.json"
        if attr_file.exists():
            with open(attr_file) as f:
                result["attribution_matrix"] = json.load(f)

        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to load case: {str(e)}")


@app.get("/api/statistics")
async def get_statistics():
    """Get overall statistics"""
    try:
        stats = {
            "total_cases": 0,
            "cases_last_24h": 0,
            "cases_last_7d": 0,
            "top_threat_actors": [],
            "top_asns": [],
            "top_countries": []
        }

        if not CASES_DIR.exists():
            return stats

        case_dirs = [d for d in CASES_DIR.iterdir() if d.is_dir()]
        stats["total_cases"] = len(case_dirs)

        # Time-based stats
        now = datetime.now()
        for case_dir in case_dirs:
            mtime = datetime.fromtimestamp(case_dir.stat().st_mtime)
            age_hours = (now - mtime).total_seconds() / 3600

            if age_hours <= 24:
                stats["cases_last_24h"] += 1
            if age_hours <= 168:  # 7 days
                stats["cases_last_7d"] += 1

        # Aggregate threat indicators from cases
        threat_actors = set()
        asns = set()
        countries = set()

        for case_dir in case_dirs:
            # Read attribution matrix if exists
            attribution_file = case_dir / "attribution_matrix.json"
            if attribution_file.exists():
                try:
                    with open(attribution_file) as f:
                        attribution = json.load(f)
                        # Extract threat actors
                        if "threat_actors" in attribution:
                            threat_actors.update(attribution.get("threat_actors", []))
                except:
                    pass

            # Read origin info for ASN and country
            origin_file = case_dir / "origin.json"
            if origin_file.exists():
                try:
                    with open(origin_file) as f:
                        origin = json.load(f)
                        if "asn" in origin:
                            asns.add(str(origin["asn"]))
                        if "cc" in origin:
                            countries.add(origin["cc"])
                except:
                    pass

        stats["unique_asns"] = len(asns)
        stats["unique_countries"] = len(countries)
        stats["threat_actors"] = list(threat_actors)[:10]  # Top 10

        return stats

    except Exception as e:
        raise HTTPException(500, f"Failed to generate statistics: {str(e)}")


@app.post("/api/query")
async def query_cases(query: CaseQuery):
    """Query cases by IP, domain, or ASN"""
    try:
        # Use PAW's index database for queries
        from paw.core.index import query_recent

        # Query cases using the index
        matches = query_recent(
            by=query.query_type,
            value=query.value,
            days=query.days
        )

        # Enhance results with full case data
        results = []
        for match in matches:
            case_id = match.get("id")
            if case_id:
                case_dir = CASES_DIR / case_id
                if case_dir.exists():
                    manifest_file = case_dir / "manifest.json"
                    if manifest_file.exists():
                        with open(manifest_file) as f:
                            manifest = json.load(f)
                            results.append({
                                "case_id": case_id,
                                "created_at": match.get("created_utc"),
                                "score": match.get("score"),
                                "origin_ip": match.get("origin_ip"),
                                "from_domain": match.get("from_domain"),
                                "manifest": manifest
                            })

        return {
            "query_type": query.query_type,
            "value": query.value,
            "matches": results,
            "total": len(results)
        }

    except Exception as e:
        raise HTTPException(500, f"Query failed: {str(e)}")


@app.get("/api/export/{case_id}")
async def export_case(case_id: str, format: str = "zip"):
    """Export case as ZIP archive"""
    import zipfile
    import tempfile
    import shutil

    try:
        case_dir = CASES_DIR / case_id

        if not case_dir.exists():
            raise HTTPException(404, "Case not found")

        # Create ZIP archive
        if format == "zip":
            # Create temporary ZIP file
            temp_dir = Path(tempfile.gettempdir())
            zip_path = temp_dir / f"{case_id}.zip"

            # Create ZIP archive recursively
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in case_dir.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(case_dir)
                        zipf.write(file_path, arcname)

            # Return ZIP file
            return FileResponse(
                zip_path,
                media_type="application/zip",
                filename=f"{case_id}.zip",
                background=BackgroundTasks()  # Cleanup temp file after response
            )

        elif format == "json":
            # Return manifest only
            manifest_file = case_dir / "manifest.json"
            if manifest_file.exists():
                return FileResponse(manifest_file, filename=f"{case_id}_manifest.json")

        raise HTTPException(400, f"Unsupported export format: {format}")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Export failed: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
