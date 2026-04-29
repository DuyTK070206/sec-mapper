from pathlib import Path

import pytest


@pytest.mark.skipif(__import__("importlib").util.find_spec("fastapi") is None, reason="fastapi not installed")
def test_web_api_health_and_scan():
    from fastapi.testclient import TestClient

    from src.web_api import create_app

    app = create_app()
    client = TestClient(app)

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    manifest = Path(__file__).resolve().parent.parent / "samples" / "package.json"
    resp = client.post("/scan", json={"manifest_path": str(manifest)})
    assert resp.status_code == 200
    data = resp.json()
    assert "findings" in data


@pytest.mark.skipif(__import__("importlib").util.find_spec("fastapi") is None, reason="fastapi not installed")
def test_web_api_async_job_flow():
    from fastapi.testclient import TestClient

    from src.web_api import create_app

    app = create_app()
    client = TestClient(app)

    manifest = Path(__file__).resolve().parent.parent / "samples" / "package.json"
    start = client.post("/jobs", json={"manifest_path": str(manifest)})
    assert start.status_code == 200
    job_id = start.json()["job_id"]

    for _ in range(20):
        status = client.get(f"/jobs/{job_id}")
        assert status.status_code == 200
        payload = status.json()
        if payload.get("status") == "done":
            break
    assert payload.get("status") == "done"


@pytest.mark.skipif(__import__("importlib").util.find_spec("fastapi") is None, reason="fastapi not installed")
def test_web_api_upload_scan_and_reports():
    from fastapi.testclient import TestClient

    from src.upload_service import UPLOAD_ROOT
    from src.web_api import create_app

    app = create_app()
    client = TestClient(app)

    manifest = Path(__file__).resolve().parent.parent / "samples" / "package.json"
    lock = Path(__file__).resolve().parent.parent / "samples" / "package-lock.json"

    with manifest.open("rb") as manifest_handle, lock.open("rb") as lock_handle:
        upload = client.post(
            "/upload",
            files=[
                ("files", ("package.json", manifest_handle, "application/json")),
                ("files", ("package-lock.json", lock_handle, "application/json")),
            ],
        )

    assert upload.status_code == 200
    upload_data = upload.json()
    assert upload_data["uploaded_filenames"] == ["package.json", "package-lock.json"]
    assert upload_data["normalized_scan_targets"]

    job_id = upload_data["job_id"]
    start = client.post("/scan-uploaded", json={"job_id": job_id})
    assert start.status_code == 200

    payload = None
    for _ in range(30):
        status = client.get(f"/jobs/{job_id}")
        assert status.status_code == 200
        payload = status.json()
        if payload.get("status") == "done":
            break

    assert payload is not None
    assert payload.get("status") == "done"
    assert payload.get("uploaded_filenames") == ["package.json", "package-lock.json"]
    assert payload.get("report_links", {}).get("json") == f"/jobs/{job_id}/report/json"

    json_report = client.get(f"/jobs/{job_id}/report/json")
    assert json_report.status_code == 200
    assert "metadata" in json_report.text

    html_report = client.get(f"/jobs/{job_id}/report/html")
    assert html_report.status_code == 200
    assert "Dependency Vulnerability Report" in html_report.text

    assert not (UPLOAD_ROOT / job_id).exists()


@pytest.mark.skipif(__import__("importlib").util.find_spec("fastapi") is None, reason="fastapi not installed")
def test_web_api_rejects_unsupported_and_traversal_uploads():
    from fastapi.testclient import TestClient

    from src.web_api import create_app

    app = create_app()
    client = TestClient(app)

    bad_type = client.post(
        "/upload",
        files=[("files", ("notes.txt", b"hello", "text/plain"))],
    )
    assert bad_type.status_code == 400
    assert "Unsupported file type" in bad_type.json()["detail"]

    traversal = client.post(
        "/upload",
        files=[("files", ("../package.json", b"{}", "application/json"))],
    )
    assert traversal.status_code == 400
    assert "Path traversal" in traversal.json()["detail"]
