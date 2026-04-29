import json
import threading
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from src.report_generator import ReportGenerator
from src.scanner import DependencyScanner
from src.upload_service import build_scan_targets, cleanup_workspace, store_uploads


JOBS: Dict[str, Dict] = {}


def _run_job(job_id: str, scan_targets: List[Dict], db_path: Optional[str]) -> None:
    try:
        scanner = DependencyScanner(db_path=db_path)
        result = scanner.scan_targets(scan_targets)
        JOBS[job_id]["result"] = result
        JOBS[job_id]["status"] = "done"
    except Exception as exc:
        JOBS[job_id]["status"] = "failed"
        JOBS[job_id]["error"] = str(exc)
    finally:
        cleanup_workspace(job_id)


def create_app(db_path: Optional[str] = None):
    try:
        from fastapi import FastAPI, File, HTTPException, UploadFile
        from fastapi.responses import HTMLResponse, PlainTextResponse
        from pydantic import BaseModel
    except ImportError as exc:
        raise RuntimeError("FastAPI is required for web mode. Install dependencies from requirements.txt.") from exc

    app = FastAPI(title="Sec Mapper API", version="2.0.0")

    class ScanRequest(BaseModel):
        manifest_path: str
        lock_path: Optional[str] = None

    class ScanUploadedRequest(BaseModel):
        job_id: str

    def _job_response(job_id: str) -> Dict:
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        payload = {
            "job_id": job_id,
            "status": job.get("status"),
            "uploaded_filenames": job.get("uploaded_filenames", []),
            "normalized_scan_targets": job.get("normalized_scan_targets", []),
            "report_links": {
                "json": f"/jobs/{job_id}/report/json",
                "html": f"/jobs/{job_id}/report/html",
                "sarif": f"/jobs/{job_id}/report/sarif",
                "api": f"/jobs/{job_id}/report/api",
            },
        }

        if job.get("status") == "done" and job.get("result"):
            payload["result"] = job["result"]

        if job.get("status") == "failed":
            payload["error"] = job.get("error")

        return payload

    @app.post("/upload")
    async def upload(files: List[UploadFile] = File(...)):
        job_id = str(uuid.uuid4())
        records = await store_uploads(job_id, files)
        JOBS[job_id] = {
            "status": "uploaded",
            "uploaded_filenames": [record.stored_filename for record in records],
            "records": [
                {
                    "original_filename": record.original_filename,
                    "stored_filename": record.stored_filename,
                    "path": str(record.path),
                    "size": record.size,
                }
                for record in records
            ],
        }
        targets = build_scan_targets(records)
        JOBS[job_id]["normalized_scan_targets"] = targets
        return {
            "job_id": job_id,
            "status": "uploaded",
            "uploaded_filenames": JOBS[job_id]["uploaded_filenames"],
            "normalized_scan_targets": targets,
            "report_links": {
                "json": f"/jobs/{job_id}/report/json",
                "html": f"/jobs/{job_id}/report/html",
                "sarif": f"/jobs/{job_id}/report/sarif",
                "api": f"/jobs/{job_id}/report/api",
            },
        }

    @app.post("/scan-uploaded")
    def scan_uploaded(req: ScanUploadedRequest):
        job = JOBS.get(req.job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.get("status") == "running":
            raise HTTPException(status_code=409, detail="Job is already running")
        if job.get("status") == "done":
            raise HTTPException(status_code=409, detail="Job has already been scanned")
        if not job.get("normalized_scan_targets"):
            raise HTTPException(status_code=400, detail="No uploaded scan targets are available for this job")

        job["status"] = "running"
        thread = threading.Thread(target=_run_job, args=(req.job_id, job["normalized_scan_targets"], db_path), daemon=True)
        thread.start()
        return {
            "job_id": req.job_id,
            "status": "running",
            "uploaded_filenames": job.get("uploaded_filenames", []),
            "normalized_scan_targets": job.get("normalized_scan_targets", []),
            "report_links": {
                "json": f"/jobs/{req.job_id}/report/json",
                "html": f"/jobs/{req.job_id}/report/html",
                "sarif": f"/jobs/{req.job_id}/report/sarif",
                "api": f"/jobs/{req.job_id}/report/api",
            },
        }

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "sec-mapper"}

    @app.get("/", response_class=HTMLResponse)
    def index():
        html = (Path(__file__).resolve().parent / "web" / "index.html").read_text(encoding="utf-8")
        return html

    @app.post("/scan")
    def scan(req: ScanRequest):
        manifest = Path(req.manifest_path)
        lock = Path(req.lock_path) if req.lock_path else None
        if not manifest.exists():
            raise HTTPException(status_code=404, detail=f"Manifest not found: {manifest}")
        if lock and not lock.exists():
            raise HTTPException(status_code=404, detail=f"Lock not found: {lock}")
        scanner = DependencyScanner(db_path=db_path)
        return scanner.scan_file(manifest, lock_path=lock)

    @app.post("/jobs")
    def create_job(req: ScanRequest):
        manifest = Path(req.manifest_path)
        lock = Path(req.lock_path) if req.lock_path else None
        if not manifest.exists():
            raise HTTPException(status_code=404, detail=f"Manifest not found: {manifest}")
        if lock and not lock.exists():
            raise HTTPException(status_code=404, detail=f"Lock not found: {lock}")

        job_id = str(uuid.uuid4())
        JOBS[job_id] = {"status": "running"}
        targets = [
            {
                "manifest_path": str(manifest),
                "lock_path": str(lock) if lock else None,
                "uploaded_filenames": [manifest.name] + ([lock.name] if lock else []),
            }
        ]
        thread = threading.Thread(target=_run_job, args=(job_id, targets, db_path), daemon=True)
        thread.start()
        JOBS[job_id]["uploaded_filenames"] = [manifest.name] + ([lock.name] if lock else [])
        JOBS[job_id]["normalized_scan_targets"] = targets
        return {
            "job_id": job_id,
            "status": "running",
            "uploaded_filenames": JOBS[job_id]["uploaded_filenames"],
            "normalized_scan_targets": targets,
            "report_links": {
                "json": f"/jobs/{job_id}/report/json",
                "html": f"/jobs/{job_id}/report/html",
                "sarif": f"/jobs/{job_id}/report/sarif",
                "api": f"/jobs/{job_id}/report/api",
            },
        }

    @app.get("/jobs/{job_id}")
    def get_job(job_id: str):
        return _job_response(job_id)

    @app.get("/jobs/{job_id}/report/{fmt}")
    def get_job_report(job_id: str, fmt: str):
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.get("status") != "done":
            raise HTTPException(status_code=409, detail="Job not completed")

        report = ReportGenerator(job["result"])
        if fmt == "json":
            return PlainTextResponse(report.generate_json_report(), media_type="application/json")
        if fmt == "sarif":
            return PlainTextResponse(report.generate_sarif_report(), media_type="application/sarif+json")
        if fmt == "html":
            return HTMLResponse(report.generate_html_report())
        if fmt == "api":
            return PlainTextResponse(report.generate_api_report(), media_type="application/json")
        raise HTTPException(status_code=400, detail="Unsupported format")

    return app


def run_server(host: str = "127.0.0.1", port: int = 8000, db_path: Optional[str] = None) -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("uvicorn is required for web mode. Install dependencies from requirements.txt.") from exc

    app = create_app(db_path=db_path)
    uvicorn.run(app, host=host, port=port)
