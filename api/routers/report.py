"""리포트 라우터 (api/routers/report.py).

Wave 2-D: 리포트 생성/다운로드/미리보기 엔드포인트를 server.py 에서 분리.
공개 URL/응답 셰이프/dependencies(verify_api_key)/상태 코드는 그대로 보존된다.

엔드포인트:
  - GET /api/report/generate
  - GET /api/report/download/{filename}
  - GET /api/report/preview

설계 메모:
  - 데이터 로드 / 의존성 스캔은 ``api.services.report_generation`` 으로
    분리되었다 (Wave 2-R). 라우터는 서비스 함수를 호출하기만 한다.
  - 다운로드 경로 산출은 ``api.result_sources.reports_path`` 헬퍼를 사용한다
    (Wave 2-Q 동작 유지).
  - reports.report_generator 의존성은 본 모듈 안에서 lazy import 하여
    api 패키지 임포트 시 의존성이 끌려오지 않도록 한다.
  - api.server 를 import 하지 않아 순환 import 위험이 없다.
"""

from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import FileResponse

from api import result_sources
from api.auth import verify_api_key
from api.services import report_generation as report_service
from api.services import safe_paths

router = APIRouter()


def _safe_report_filename(filename: str) -> str:
    """다운로드 요청 파일명을 sanitize 한다 (Wave 3-B: ``safe_paths`` 위임).

    Wave 2-Q 의 inline 표현식을 Wave 3-B 에서 ``safe_paths.sanitize_filename``
    으로 모았다. 동작(``/``, ``\\`` → ``_``)은 그대로 보존된다.
    """
    return safe_paths.sanitize_filename(filename)


@router.get("/api/report/generate", dependencies=[Depends(verify_api_key)])
def generate_report(
    fmt: str = Query("html", description="md, html, both"),
    session_id: Optional[str] = Query(None, description="세션 ID (없으면 최신)"),
    include_deps: bool = Query(False, description="의존성 스캔 포함"),
):
    """분석 리포트를 생성하고 다운로드 경로를 반환합니다."""
    from reports.report_generator import ReportGenerator

    data = report_service.load_report_data(session_id)
    if not data:
        return {"error": "분석 데이터가 없습니다. 먼저 코드 분석을 실행하세요."}

    deps_data = report_service.scan_dependencies_safely() if include_deps else None

    gen = ReportGenerator()
    result = gen.save_report(
        data, output_dir=result_sources.REPORTS_DIR, fmt=fmt, include_deps=deps_data,
    )

    return {
        "status": "generated",
        "files": result,
        "download_urls": {
            k: f"/api/report/download/{safe_paths.report_download_basename(v)}"
            for k, v in result.items()
        },
    }


@router.get("/api/report/download/{filename}", dependencies=[Depends(verify_api_key)])
def download_report(filename: str):
    """생성된 리포트 파일을 다운로드합니다."""
    safe_name = _safe_report_filename(filename)
    path = result_sources.reports_path(safe_name)
    if not os.path.exists(path):
        return {"error": "리포트 파일을 찾을 수 없습니다."}

    media_type = "text/html" if path.endswith(".html") else "text/markdown"
    return FileResponse(path, media_type=media_type, filename=safe_name)


@router.get("/api/report/preview", dependencies=[Depends(verify_api_key)])
def preview_report(
    session_id: Optional[str] = Query(None),
    include_deps: bool = Query(False),
):
    """리포트를 생성하고 HTML 내용을 바로 반환합니다 (미리보기)."""
    from reports.report_generator import ReportGenerator

    data = report_service.load_report_data(session_id)
    if not data:
        return {"error": "분석 데이터가 없습니다."}

    deps_data = report_service.scan_dependencies_safely() if include_deps else None

    gen = ReportGenerator()
    html = gen.generate_html(data, deps_data)
    md = gen.generate_markdown(data, deps_data)

    return {"html": html, "markdown": md}
