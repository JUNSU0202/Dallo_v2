"""빠른 스캔 라우터 (api/routers/quick_scan.py).

Wave 2-C: api/server.py 에서 분리된 정규식 기반 빠른 스캔 엔드포인트.
공개 URL/응답 셰이프/인증 의존성은 그대로 보존된다.

엔드포인트:
  - POST /api/quick-scan
  - POST /api/quick-scan-project

도메인 로직(룰/스캐너)은 analyzer/quick_scan.py 모듈에 위치한다.
"""

from __future__ import annotations

import time
from typing import List

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from analyzer.quick_scan import detect_language, scan
from api.auth import verify_api_key

router = APIRouter()


class QuickScanRequest(BaseModel):
    code: str
    language: str = "python"


class ProjectScanRequest(BaseModel):
    files: List[dict]  # [{"path": "src/app.py", "code": "..."}]


@router.post("/api/quick-scan", dependencies=[Depends(verify_api_key)])
def quick_scan(req: QuickScanRequest):
    """정규식 기반 빠른 스캔 — 프로세스 실행 없이 밀리초 단위 응답"""
    language = req.language or "python"
    start = time.time()
    findings = scan(req.code, language)
    elapsed_ms = round((time.time() - start) * 1000, 1)
    return {
        "findings": findings,
        "count": len(findings),
        "elapsed_ms": elapsed_ms,
        "scan_type": "quick",
    }


@router.post("/api/quick-scan-project", dependencies=[Depends(verify_api_key)])
def quick_scan_project(req: ProjectScanRequest):
    """프로젝트 전체 빠른 스캔 — 여러 파일을 한 번에 분석"""
    start = time.time()
    file_results = []
    total_findings = 0
    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for f in req.files:
        fpath = f.get("path", "unknown")
        code = f.get("code", "")
        lang = detect_language(fpath)
        findings = scan(code, lang)
        for finding in findings:
            summary[finding["severity"]] = summary.get(finding["severity"], 0) + 1
        total_findings += len(findings)
        file_results.append({
            "path": fpath,
            "language": lang,
            "findings": findings,
            "count": len(findings),
        })

    file_results.sort(key=lambda x: x["count"], reverse=True)
    elapsed_ms = round((time.time() - start) * 1000, 1)

    return {
        "files": file_results,
        "total_files": len(file_results),
        "total_findings": total_findings,
        "summary": summary,
        "elapsed_ms": elapsed_ms,
    }
