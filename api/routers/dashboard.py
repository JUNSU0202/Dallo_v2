"""대시보드/조회 전용 라우터 (api/routers/dashboard.py).

Wave 2-B: 부수효과 없는 GET 엔드포인트만 server.py 에서 분리.
공개 URL/응답 셰이프/dependencies/response_model 은 그대로 보존한다.

이동된 엔드포인트:
  - GET /api/stats
  - GET /api/vulnerabilities
  - GET /api/vulnerabilities/by-file
  - GET /api/vulnerabilities/by-type
  - GET /api/patches
  - GET /api/sessions
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query

from api import result_sources
from api.auth import verify_api_key
from api.dto.responses import (
    PatchesResponse,
    SessionsResponse,
    StatsResponse,
    VulnerabilitiesByFileResponse,
    VulnerabilitiesByTypeResponse,
    VulnerabilitiesResponse,
)
from db import service as db_service

router = APIRouter()


@router.get(
    "/api/stats",
    response_model=StatsResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def get_stats():
    """대시보드 메인 통계 (DB 우선, 폴백: JSON 파일)"""
    stats = db_service.get_stats()
    if stats.get("total_issues", 0) > 0:
        return stats

    # DB에 데이터 없으면 JSON 파일 폴백
    full = result_sources.load_full_result()
    if full:
        summary = full.get("summary", {})
        return {
            "total_issues": summary.get("total", 0),
            "high": summary.get("high", 0),
            "medium": summary.get("medium", 0),
            "low": summary.get("low", 0),
            "patches_generated": summary.get("patches_generated", 0),
            "patches_verified": summary.get("patches_verified", 0),
            "duration_seconds": full.get("duration_seconds"),
            "session_id": full.get("session_id", ""),
        }

    report = result_sources.load_bandit_report()
    totals = report.get("metrics", {}).get("_totals", {})
    results = report.get("results", [])
    return {
        "total_issues": len(results),
        "high": totals.get("SEVERITY.HIGH", 0),
        "medium": totals.get("SEVERITY.MEDIUM", 0),
        "low": totals.get("SEVERITY.LOW", 0),
        "patches_generated": 0,
        "patches_verified": 0,
    }


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
    full = result_sources.load_full_result()

    if full and full.get("vulnerabilities"):
        vulns = full["vulnerabilities"]
    else:
        report = result_sources.load_bandit_report()
        vulns = []
        for item in report.get("results", []):
            cwe = item.get("issue_cwe", {})
            vulns.append({
                "id": f"vuln_{item.get('test_id', '')}_{item.get('line_number', 0)}",
                "tool": "bandit",
                "rule_id": item.get("test_id", ""),
                "title": item.get("test_name", ""),
                "severity": item.get("issue_severity", ""),
                "confidence": item.get("issue_confidence", ""),
                "description": item.get("issue_text", ""),
                "file_path": item.get("filename", ""),
                "line_number": item.get("line_number", 0),
                "code_snippet": item.get("code", ""),
                "cwe_id": f"CWE-{cwe['id']}" if isinstance(cwe, dict) and cwe.get("id") else None,
                "more_info": item.get("more_info", ""),
            })

    # 필터
    if severity:
        vulns = [v for v in vulns if v.get("severity", "").upper() == severity.upper()]
    if tool:
        vulns = [v for v in vulns if v.get("tool", "").lower() == tool.lower()]
    if file_path:
        vulns = [v for v in vulns if file_path in v.get("file_path", "")]

    return {"count": len(vulns), "vulnerabilities": vulns}


@router.get(
    "/api/vulnerabilities/by-file",
    response_model=VulnerabilitiesByFileResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def get_vulnerabilities_by_file():
    """파일별 취약점 수 집계"""
    data = get_vulnerabilities(severity=None, tool=None, file_path=None)
    vulns = data["vulnerabilities"]

    file_counts = {}
    for v in vulns:
        fp = v.get("file_path", "unknown")
        if fp not in file_counts:
            file_counts[fp] = {"file": fp, "high": 0, "medium": 0, "low": 0, "total": 0}
        sev = v.get("severity", "LOW").lower()
        if sev in file_counts[fp]:
            file_counts[fp][sev] += 1
        file_counts[fp]["total"] += 1

    return {"files": list(file_counts.values())}


@router.get(
    "/api/vulnerabilities/by-type",
    response_model=VulnerabilitiesByTypeResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def get_vulnerabilities_by_type():
    """취약점 유형별 집계"""
    data = get_vulnerabilities(severity=None, tool=None, file_path=None)
    vulns = data["vulnerabilities"]

    type_counts = {}
    for v in vulns:
        rule = v.get("rule_id", "unknown")
        name = v.get("title", "unknown")
        key = f"{rule}:{name}"
        if key not in type_counts:
            type_counts[key] = {"rule_id": rule, "name": name, "count": 0, "severity": v.get("severity", "")}
        type_counts[key]["count"] += 1

    return {"types": list(type_counts.values())}


@router.get(
    "/api/patches",
    response_model=PatchesResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def get_patches():
    """LLM 수정 제안 목록"""
    full = result_sources.load_full_result()
    patches = full.get("patches", [])

    # 취약점 정보와 매칭
    vulns = {v.get("id"): v for v in full.get("vulnerabilities", [])}
    enriched = []
    for p in patches:
        vuln = vulns.get(p.get("vulnerability_id"), {})
        enriched.append({
            **p,
            "file_path": vuln.get("file_path", ""),
            "line_number": vuln.get("line_number", 0),
            "rule_id": vuln.get("rule_id", ""),
            "severity": vuln.get("severity", ""),
            "title": vuln.get("title", ""),
            "original_code": vuln.get("function_code") or vuln.get("code_snippet", ""),
        })

    return {"count": len(enriched), "patches": enriched}


@router.get(
    "/api/sessions",
    response_model=SessionsResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def get_sessions():
    """분석 세션 이력 (DB)"""
    sessions = db_service.get_all_sessions()
    return {"count": len(sessions), "sessions": sessions}
