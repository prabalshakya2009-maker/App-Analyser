import os
import json
import uuid
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, Request, HTTPException, status
from fastapi.responses import PlainTextResponse
from ..core.config import settings
from ..core.security import SecurityValidator, rate_limiter
from ..models.schemas import SeverityLevel
from ..engines.pe_analyzer import PEAnalyzer
from ..engines.apk_analyzer import APKAnalyzer
from ..engines.scoring import ScoringEngine

router = APIRouter()
pe_analyzer = PEAnalyzer()
apk_analyzer = APKAnalyzer()

def format_frontend_report(safe_filename: str, ext: str, bytes_read: int, hashes: dict, findings: list, static_details: dict) -> dict:
    summary, improvements, hardening_prompt = ScoringEngine.evaluate(findings, ext, safe_filename)

    frontend_findings = []
    for f in findings:
        frontend_findings.append({
            "severity": f.severity.value.lower(),
            "title": f.title,
            "description": f.description,
            "cwe": f.cwe,
            "cve": f.cwe,
            "remediation": f.remediation,
            "recommendation": f.remediation,
            "location": f.evidence or f.category,
            "evidence": f.evidence,
            "category": f.category
        })

    bugs_list = [f for f in frontend_findings if f["severity"] in ["medium", "low", "info"]]
    sec_list = [f for f in frontend_findings if f["severity"] in ["critical", "high"]]

    return {
        "fileName": safe_filename,
        "fileType": ext.lstrip('.').upper(),
        "fileSize": bytes_read,
        "hackabilityScore": summary.hackabilityScore,
        "criticalCount": summary.criticalCount,
        "bugCount": len(bugs_list),
        "bugs": bugs_list,
        "securityFindings": sec_list,
        "improvements": improvements,
        "aiSummary": summary.executiveSummary,
        "fixPrompt": hardening_prompt,
        "staticInfo": {
            "sha256": hashes.get("sha256", "N/A"),
            "md5": hashes.get("md5", "N/A"),
            "format": static_details.get("format", ext.lstrip('.').upper()),
            "is_signed": static_details.get("isSigned", False),
            "production_gate": summary.productionGate.value
        },
        "sandboxResults": {
            "status": "completed",
            "logs": [
                f"Binary integrity & static mitigation check complete for {safe_filename}.",
                f"Assessed {len(findings)} total security parameters.",
                f"Production Gate Decision: {summary.productionGate.value}."
            ]
        }
    }

@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "timestamp": datetime.utcnow().isoformat()
    }

@router.post("/analyze")
async def analyze_artifact(request: Request, file: UploadFile = File(...)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not rate_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please wait before submitting more files."
        )

    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No file provided")

    safe_filename = SecurityValidator.sanitize_filename(file.filename)
    ext = os.path.splitext(safe_filename)[1].lower()

    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format '{ext}'. Only .apk and .exe artifacts are accepted."
        )

    report_id = str(uuid.uuid4())
    temp_path = settings.STORAGE_DIR / f"{report_id}{ext}"

    bytes_read = 0
    with open(temp_path, "wb") as f:
        while chunk := await file.read(1024 * 1024):
            bytes_read += len(chunk)
            if bytes_read > settings.MAX_FILE_SIZE_BYTES:
                f.close()
                temp_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Artifact size exceeds the maximum permitted limit ({settings.MAX_FILE_SIZE_BYTES // (1024*1024)} MB)"
                )
            f.write(chunk)

    try:
        if ext == ".exe":
            if not SecurityValidator.validate_pe_binary(temp_path):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Corrupt or invalid PE executable format")
            analysis_data = pe_analyzer.analyze(temp_path)
        else:
            is_valid, err_msg = SecurityValidator.validate_apk_package(temp_path)
            if not is_valid:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg or "Invalid APK package")
            analysis_data = apk_analyzer.analyze(temp_path)

        hashes = SecurityValidator.compute_file_hashes(temp_path)
        findings = analysis_data["findings"]
        static_details = analysis_data["staticDetails"]

        formatted_report = format_frontend_report(
            safe_filename, ext, bytes_read, hashes, findings, static_details
        )

        record = {
            "reportId": report_id,
            "status": "done",
            "report": formatted_report
        }

        report_file = settings.REPORT_DIR / f"{report_id}.json"
        with open(report_file, "w", encoding="utf-8") as rf:
            json.dump(record, rf, indent=2)

        return {
            "reportId": report_id,
            "status": "done",
            "report": formatted_report
        }

    finally:
        temp_path.unlink(missing_ok=True)

@router.get("/report/{report_id}")
@router.get("/reports/{report_id}")
def get_report(report_id: str):
    clean_id = SecurityValidator.sanitize_filename(report_id)
    report_file = settings.REPORT_DIR / f"{clean_id}.json"
    if not report_file.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis report not found")

    with open(report_file, "r", encoding="utf-8") as rf:
        data = json.load(rf)
    return data

@router.get("/report/{report_id}/markdown", response_class=PlainTextResponse)
@router.get("/reports/{report_id}/markdown", response_class=PlainTextResponse)
def get_report_markdown(report_id: str):
    clean_id = SecurityValidator.sanitize_filename(report_id)
    report_file = settings.REPORT_DIR / f"{clean_id}.json"
    if not report_file.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis report not found")

    with open(report_file, "r", encoding="utf-8") as rf:
        data = json.load(rf)

    rep = data.get("report", {})
    fileName = rep.get("fileName", clean_id)
    fileType = rep.get("fileType", "UNKNOWN")
    score = rep.get("hackabilityScore", "N/A")
    aiSummary = rep.get("aiSummary", "")
    findings = rep.get("securityFindings", []) + rep.get("bugs", [])
    improvements = rep.get("improvements", [])

    md = f"""# Security Posture & Production Readiness Report

**Artifact:** `{fileName}` ({fileType})  
**Hackability Score:** **{score} / 10.0**  
**Summary:** {aiSummary}

---

## Findings Matrix

| Severity | Title | CWE | Recommendation |
| :--- | :--- | :--- | :--- |
"""
    for f in findings:
        md += f"| **{f.get('severity', '').upper()}** | {f.get('title')} | `{f.get('cwe')}` | {f.get('remediation')} |\n"

    md += """
---

## Production Readiness Improvements
"""
    for i, imp in enumerate(improvements, 1):
        md += f"{i}. {imp}\n"

    return md
