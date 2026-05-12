"""빠른 스캔 라우터 (api/routers/quick_scan.py).

Wave 2-C: api/server.py 에서 분리된 정규식 기반 빠른 스캔 엔드포인트.
공개 URL/응답 셰이프/인증 의존성은 그대로 보존된다.

Wave 4-Y: elapsed 측정용 ``time.time()`` 호출을 모듈 레벨 ``_clock`` callable
+ ``set_clock()`` / ``reset_clock()`` seam 으로 분리한다. 두 엔드포인트
모두 동일한 ``_clock()`` seam 만 통과하므로 fake clock 으로 ``elapsed_ms``
를 결정적으로 검증할 수 있다. ``_clock`` 의 기본 reference 는 여전히
``time.time`` 이라 운영 동작/응답 shape/인증 의존성/quick scan finding shape
는 한 글자도 바뀌지 않는다.

엔드포인트:
  - POST /api/quick-scan
  - POST /api/quick-scan-project

도메인 로직(룰/스캐너)은 analyzer/quick_scan.py 모듈에 위치한다.
"""

from __future__ import annotations

import time
from typing import Callable, List

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from analyzer.quick_scan import detect_language, scan
from api.auth import verify_api_key

router = APIRouter()


# ============================================================
# Wave 4-Y: elapsed clock seam
# ============================================================
# ``_clock`` 은 운영 경로에서는 ``time.time`` 을 가리키고, 테스트가
# ``set_clock(fake)`` 를 호출하면 fake callable 로 교체된다.
# 두 엔드포인트는 직접 ``time.time()`` 을 호출하지 않고 ``_clock()`` 만
# 통과해야 한다 (AST guard 가 회귀 차단).

_clock: Callable[[], float] = time.time


def set_clock(clock: Callable[[], float]) -> None:
    """fake clock 을 주입한다. 테스트 종료 시 ``reset_clock()`` 으로 복귀해야 한다."""
    global _clock
    _clock = clock


def reset_clock() -> None:
    """``_clock`` 을 운영 default(``time.time``) 로 되돌린다."""
    global _clock
    _clock = time.time


def _elapsed_ms(start: float) -> float:
    """start 이후 경과 시간을 밀리초(소수 첫째 자리 반올림) 로 반환."""
    return round((_clock() - start) * 1000, 1)


class QuickScanRequest(BaseModel):
    code: str
    language: str = "python"


class ProjectScanRequest(BaseModel):
    files: List[dict]  # [{"path": "src/app.py", "code": "..."}]


@router.post("/api/quick-scan", dependencies=[Depends(verify_api_key)])
def quick_scan(req: QuickScanRequest):
    """정규식 기반 빠른 스캔 — 프로세스 실행 없이 밀리초 단위 응답"""
    language = req.language or "python"
    start = _clock()
    findings = scan(req.code, language)
    elapsed_ms = _elapsed_ms(start)
    return {
        "findings": findings,
        "count": len(findings),
        "elapsed_ms": elapsed_ms,
        "scan_type": "quick",
    }


@router.post("/api/quick-scan-project", dependencies=[Depends(verify_api_key)])
def quick_scan_project(req: ProjectScanRequest):
    """프로젝트 전체 빠른 스캔 — 여러 파일을 한 번에 분석"""
    start = _clock()
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
    elapsed_ms = _elapsed_ms(start)

    return {
        "files": file_results,
        "total_files": len(file_results),
        "total_findings": total_findings,
        "summary": summary,
        "elapsed_ms": elapsed_ms,
    }
