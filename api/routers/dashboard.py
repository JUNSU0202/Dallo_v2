"""대시보드/조회 전용 라우터 (api/routers/dashboard.py).

Wave 2-B: 부수효과 없는 GET 엔드포인트만 server.py 에서 분리.
Wave 2-M: 비즈니스 로직(stats DB-우선/JSON 폴백, Bandit 폴백 변환, 필터링,
by-file/by-type 집계, 패치 enrichment, sessions 조회) 을
``api.services.dashboard_queries`` 로 이동. 라우터는 요청 파싱 + auth +
서비스 호출만 담당한다. 공개 URL/응답 셰이프/dependencies/response_model
은 그대로 보존된다.

이동된 엔드포인트:
  - GET /api/stats
  - GET /api/vulnerabilities
  - GET /api/vulnerabilities/by-file
  - GET /api/vulnerabilities/by-type
  - GET /api/patches
  - GET /api/sessions
  - GET /api/sessions/{session_id}   (Wave 2-C)
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query

from api.auth import verify_api_key
from api.dto.responses import (
    PatchesResponse,
    SessionsResponse,
    StatsResponse,
    VulnerabilitiesByFileResponse,
    VulnerabilitiesByTypeResponse,
    VulnerabilitiesResponse,
)
from api.services import dashboard_queries

router = APIRouter()


@router.get(
    "/api/stats",
    response_model=StatsResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def get_stats():
    """대시보드 메인 통계 (DB 우선, 폴백: JSON 파일)"""
    return dashboard_queries.get_stats()


@router.get(
    "/api/vulnerabilities",
    response_model=VulnerabilitiesResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def get_vulnerabilities(
    severity: Optional[str] = Query(None, description="HIGH, MEDIUM, LOW"),
    tool: Optional[str] = Query(None, description="bandit, sonarqube"),
    file_path: Optional[str] = Query(None, description="파일 경로 필터"),
):
    """취약점 목록 조회 (필터 지원)"""
    return dashboard_queries.get_vulnerabilities(
        severity=severity, tool=tool, file_path=file_path,
    )


@router.get(
    "/api/vulnerabilities/by-file",
    response_model=VulnerabilitiesByFileResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def get_vulnerabilities_by_file():
    """파일별 취약점 수 집계"""
    return dashboard_queries.get_vulnerabilities_by_file()


@router.get(
    "/api/vulnerabilities/by-type",
    response_model=VulnerabilitiesByTypeResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def get_vulnerabilities_by_type():
    """취약점 유형별 집계"""
    return dashboard_queries.get_vulnerabilities_by_type()


@router.get(
    "/api/patches",
    response_model=PatchesResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def get_patches():
    """LLM 수정 제안 목록"""
    return dashboard_queries.get_patches()


@router.get(
    "/api/sessions",
    response_model=SessionsResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def get_sessions():
    """분석 세션 이력 (DB)"""
    return dashboard_queries.get_sessions()


@router.get(
    "/api/sessions/{session_id}",
    dependencies=[Depends(verify_api_key)],
)
def get_session_detail(session_id: str):
    """특정 세션 상세 조회.

    Wave 2-C: server.py 에서 이동. 전용 DTO 가 아직 없어 response_model 은
    의도적으로 두지 않는다 — 핸들러가 반환하는 dict 셰이프를 그대로 노출한다.
    """
    return dashboard_queries.get_session_detail(session_id)
