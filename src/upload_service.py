from dataclasses import dataclass
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List

from fastapi import HTTPException, UploadFile, status

from src.dependency_parser import ParserFactory


UPLOAD_ROOT = Path(tempfile.gettempdir()) / "sec-mapper" / "uploads"
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ARCHIVE_SUFFIXES = (
    ".zip",
    ".tar",
    ".tgz",
    ".tar.gz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".7z",
    ".rar",
)
SUPPORTED_FILENAMES = {name.lower() for name in ParserFactory._registry}


@dataclass
class UploadRecord:
    original_filename: str
    stored_filename: str
    path: Path
    size: int


def create_workspace(job_id: str) -> Path:
    workspace = UPLOAD_ROOT / job_id
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


def cleanup_workspace(job_id: str) -> None:
    shutil.rmtree(UPLOAD_ROOT / job_id, ignore_errors=True)


def validate_upload_filename(filename: str) -> str:
    if not filename or not filename.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Upload filename is required")

    cleaned = Path(filename).name
    if cleaned != filename or any(sep in filename for sep in ("/", "\\")):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Path traversal filenames are not allowed")

    lower_name = cleaned.lower()
    if lower_name.endswith(ARCHIVE_SUFFIXES):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Archive uploads are not supported. Upload dependency manifests or lockfiles directly so the scanner never extracts untrusted archives.",
        )

    if lower_name not in SUPPORTED_FILENAMES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type: {cleaned}. Supported files are: {', '.join(sorted(ParserFactory._registry))}",
        )

    return cleaned


async def store_uploads(job_id: str, uploads: List[UploadFile]) -> List[UploadRecord]:
    if not uploads:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="At least one file must be uploaded")

    workspace = create_workspace(job_id)
    records: List[UploadRecord] = []
    seen = set()

    try:
        for upload in uploads:
            filename = validate_upload_filename(upload.filename or "")
            lower_name = filename.lower()
            if lower_name in seen:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Duplicate uploaded filename: {filename}")
            seen.add(lower_name)

            destination = workspace / filename
            size = 0
            with destination.open("wb") as handle:
                while True:
                    chunk = await upload.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_UPLOAD_BYTES:
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail=f"File too large: {filename}. Maximum supported upload size is {MAX_UPLOAD_BYTES} bytes.",
                        )
                    handle.write(chunk)

            if size == 0:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Uploaded file is empty: {filename}")

            records.append(UploadRecord(original_filename=upload.filename or filename, stored_filename=filename, path=destination, size=size))
            await upload.close()
    except Exception:
        cleanup_workspace(job_id)
        raise

    return records


def build_scan_targets(records: List[UploadRecord]) -> List[Dict]:
    records_by_name = {record.stored_filename.lower(): record for record in records}
    targets: List[Dict] = []
    used = set()

    npm_manifest = records_by_name.get("package.json")
    npm_lock = records_by_name.get("package-lock.json")
    if npm_manifest:
        target = {
            "manifest_path": str(npm_manifest.path),
            "lock_path": str(npm_lock.path) if npm_lock else None,
            "uploaded_filenames": [npm_manifest.stored_filename],
            "ecosystem": "npm",
        }
        if npm_lock:
            target["uploaded_filenames"].append(npm_lock.stored_filename)
            used.add("package-lock.json")
        used.add("package.json")
        targets.append(target)
    elif npm_lock:
        targets.append(
            {
                "manifest_path": str(npm_lock.path),
                "lock_path": None,
                "uploaded_filenames": [npm_lock.stored_filename],
                "ecosystem": "npm",
            }
        )
        used.add("package-lock.json")

    for record in records:
        lower_name = record.stored_filename.lower()
        if lower_name in used:
            continue
        targets.append(
            {
                "manifest_path": str(record.path),
                "lock_path": None,
                "uploaded_filenames": [record.stored_filename],
                "ecosystem": _ecosystem_for_filename(lower_name),
            }
        )

    if not targets:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No supported scan targets were found in the uploaded files")

    return targets


def _ecosystem_for_filename(filename: str) -> str:
    if filename in {"requirements.txt", "poetry.lock", "pipfile.lock"}:
        return "pip"
    if filename == "pom.xml":
        return "maven"
    if filename == "go.mod":
        return "go"
    if filename == "cargo.toml":
        return "cargo"
    if filename in {"package.json", "package-lock.json"}:
        return "npm"
    return "unknown"