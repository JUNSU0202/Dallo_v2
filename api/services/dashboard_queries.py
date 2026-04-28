"""대시보드 / 조회 전용 서비스 (api/services/dashboard_queries.py).

Wave 2-M: ``api/routers/dashboard.py`` 에 들어 있던 read-only 비즈니스 로직
(stats DB-우선/JSON 폴백, Bandit 폴백 변환, 필터링, by-file/by-type 집계,
패치 enrichment, sessions 조회) 을 HTTP 계층 외부로 분리한 모듈.

설계 원칙:
  - FastAPI / Pydantic / 응답 DTO 의존 없음. 순수 함수 + dict 반환.
  - ``api.server`` 를 import 하지 않는다 (순환 import 방지).
  - 데이터 소스(``api.result_sources`` / ``db.service``) 는 모듈 레벨에서
    import 하여 단위 테스트가 ``monkeypatch.setattr`` 로 동일 모듈에 접근
    하면 fake 로 교체할 수 있게 한다.
  - 응답 셰이프는 라우터의 기존 동작과 정확히 일치해야 한다 (response_model
    + ``response_model_exclude_unset=True`` 가 라우터 단에서 그대로 작동).
"""

from __future__ import annotations

from typing import Optional

from api import result_sources
from db import service as db_service


def get_stats() -> dict:
    """대시보드 메인 통계 — DB 우선, 없으면 full_result.json, 없으면 Bandit 폴백."""
    stats = db_service.get_stats()
    if stats.get("total_issues", 0) > 0:
        return stats

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


def _load_vulnerabilities_raw() -> list[dict]:
    """full_result.json 우선, 없으면 Bandit 리포트를 변환해 통일된 셰이프로 반환."""
    full = result_sources.load_full_result()
    if full and full.get("vulnerabilities"):
        return list(full["vulnerabilities"])

    report = result_sources.load_bandit_report()
    vulns: list[dict] = []
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
    return vulns


def get_vulnerabilities(
    severity: Optional[str] = None,
    tool: Optional[str] = None,
    file_path: Optional[str] = None,
) -> dict:
    """취약점 목록 조회 — severity/tool/file_path 필터 지원."""
    vulns = _load_vulnerabilities_raw()

    if severity:
        vulns = [v for v in vulns if v.get("severity", "").upper() == severity.upper()]
    if tool:
        vulns = [v for v in vulns if v.get("tool", "").lower() == tool.lower()]
    if file_path:
        vulns = [v for v in vulns if file_path in v.get("file_path", "")]

    return {"count": len(vulns), "vulnerabilities": vulns}


def get_vulnerabilities_by_file() -> dict:
    """파일별 취약점 수 집계."""
    vulns = get_vulnerabilities()["vulnerabilities"]

    file_counts: dict[str, dict] = {}
    for v in vulns:
        fp = v.get("file_path", "unknown")
        if fp not in file_counts:
            file_counts[fp] = {"file": fp, "high": 0, "medium": 0, "low": 0, "total": 0}
        sev = v.get("severity", "LOW").lower()
        if sev in file_counts[fp]:
            file_counts[fp][sev] += 1
        file_counts[fp]["total"] += 1

    return {"files": list(file_counts.values())}


def get_vulnerabilities_by_type() -> dict:
    """취약점 유형별 집계 (rule_id + title)."""
    vulns = get_vulnerabilities()["vulnerabilities"]

    type_counts: dict[str, dict] = {}
    for v in vulns:
        rule = v.get("rule_id", "unknown")
        name = v.get("title", "unknown")
        key = f"{rule}:{name}"
        if key not in type_counts:
            type_counts[key] = {
                "rule_id": rule, "name": name, "count": 0,
                "severity": v.get("severity", ""),
            }
        type_counts[key]["count"] += 1

    return {"types": list(type_counts.values())}


def get_patches() -> dict:
    """LLM 수정 제안 목록 — 취약점 메타로 enrichment."""
    full = result_sources.load_full_result()
    patches = full.get("patches", [])

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


def get_sessions() -> dict:
    """분석 세션 이력 (DB)."""
    sessions = db_service.get_all_sessions()
    return {"count": len(sessions), "sessions": sessions}


def get_session_detail(session_id: str) -> dict:
    """특정 세션 상세 — 미존재 시 ``{"error": "Session not found"}``."""
    result = db_service.get_analysis_by_session(session_id)
    if not result:
        return {"error": "Session not found"}
    return result


__all__ = [
    "get_stats",
    "get_vulnerabilities",
    "get_vulnerabilities_by_file",
    "get_vulnerabilities_by_type",
    "get_patches",
    "get_sessions",
    "get_session_detail",
]
