"""
DB 서비스 레이어 (db/service.py)

분석 결과를 DB에 저장하고 조회하는 함수들입니다.
API 서버와 파이프라인에서 이 모듈을 호출합니다.

사용법:
    from db.service import save_analysis, get_latest_analysis, get_all_sessions

    # 분석 결과 저장
    save_analysis(session_dict)

    # 최신 분석 결과 조회
    result = get_latest_analysis()

    # 세션 이력 조회
    sessions = get_all_sessions()

Wave 2-J: ``sys.path.insert`` 부트스트랩 해킹 제거. 모든 호출 경로(uvicorn /
celery / pytest / scripts) 가 프로젝트 루트를 cwd 또는 ``pythonpath`` 로 잡고
있어 ``db.*`` / ``shared.*`` 임포트가 표준 패키지 탐색으로 해결된다.
"""

from datetime import datetime
from typing import Optional

from db.models import SessionLocal, AnalysisRun, Vulnerability, Patch, init_db
from shared.encryption import CodeEncryptor

_encryptor = CodeEncryptor()


def save_analysis(data: dict) -> str:
    """
    전체 파이프라인 결과를 DB에 저장합니다.

    Args:
        data: AnalysisSession.to_dict() 형태의 딕셔너리
              (reports/full_result.json과 동일 구조)

    Returns:
        저장된 session_id
    """
    session_id = data.get("session_id", f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    with SessionLocal() as db:
        # 같은 session_id가 있으면 관련 데이터 모두 삭제 후 재저장
        existing = db.query(AnalysisRun).filter_by(session_id=session_id).first()
        if existing:
            for v in existing.vulnerabilities:
                for p in v.patches:
                    db.delete(p)
                db.delete(v)
            db.delete(existing)
            db.commit()

        # AnalysisRun 생성
        summary = data.get("summary", {})
        run = AnalysisRun(
            session_id=session_id,
            repo=data.get("repo", "unknown"),
            pr_number=data.get("pr_number", 0),
            commit_sha=data.get("commit_sha", ""),
            branch=data.get("branch", ""),
            total_issues=summary.get("total", 0),
            high_count=summary.get("high", 0),
            medium_count=summary.get("medium", 0),
            low_count=summary.get("low", 0),
            patches_generated=summary.get("patches_generated", 0),
            patches_verified=summary.get("patches_verified", 0),
            started_at=_parse_dt(data.get("started_at")),
            completed_at=_parse_dt(data.get("completed_at")),
            duration_seconds=data.get("duration_seconds"),
        )
        db.add(run)
        db.flush()  # run.id 확보

        # Vulnerabilities 저장
        vuln_id_map = {}  # vuln_id str → DB id 매핑
        for v in data.get("vulnerabilities", []):
            vuln = Vulnerability(
                vuln_id=v.get("id", ""),
                run_id=run.id,
                tool=v.get("tool", ""),
                rule_id=v.get("rule_id", ""),
                severity=v.get("severity", ""),
                confidence=v.get("confidence", ""),
                title=v.get("title", ""),
                description=v.get("description", ""),
                cwe_id=v.get("cwe_id"),
                file_path=v.get("file_path", ""),
                line_number=v.get("line_number", 0),
                code_snippet=_encryptor.encrypt(v.get("code_snippet", "")),
                function_code=_encryptor.encrypt(v.get("function_code", "")),
            )
            db.add(vuln)
            db.flush()
            vuln_id_map[v.get("id", "")] = vuln.id

        # Patches 저장
        for p in data.get("patches", []):
            vuln_db_id = vuln_id_map.get(p.get("vulnerability_id", ""))
            if not vuln_db_id:
                continue
            patch = Patch(
                vulnerability_id=vuln_db_id,
                fixed_code=_encryptor.encrypt(p.get("fixed_code", "")),
                explanation=p.get("explanation", ""),
                fix_type=p.get("fix_type", "recommended"),
                status=_normalize_status(p.get("status", "pending")),
                syntax_valid=p.get("syntax_valid"),
                test_passed=p.get("test_passed"),
                created_at=_parse_dt(p.get("created_at")),
            )
            db.add(patch)

        db.commit()

    return session_id


def get_latest_analysis() -> Optional[dict]:
    """가장 최근 분석 결과를 조회합니다."""
    with SessionLocal() as db:
        run = db.query(AnalysisRun).order_by(AnalysisRun.id.desc()).first()
        if not run:
            return None
        return _run_to_dict(db, run)


def get_analysis_by_session(session_id: str) -> Optional[dict]:
    """특정 세션 ID의 분석 결과를 조회합니다."""
    with SessionLocal() as db:
        run = db.query(AnalysisRun).filter_by(session_id=session_id).first()
        if not run:
            return None
        return _run_to_dict(db, run)


def get_all_sessions(limit: int = 50) -> list[dict]:
    """분석 세션 이력을 조회합니다."""
    with SessionLocal() as db:
        runs = db.query(AnalysisRun).order_by(AnalysisRun.id.desc()).limit(limit).all()
        return [
            {
                "session_id": r.session_id,
                "repo": r.repo,
                "pr_number": r.pr_number,
                "commit_sha": r.commit_sha,
                "total_issues": r.total_issues,
                "high_count": r.high_count,
                "medium_count": r.medium_count,
                "low_count": r.low_count,
                "patches_generated": r.patches_generated,
                "patches_verified": r.patches_verified,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                "duration_seconds": r.duration_seconds,
            }
            for r in runs
        ]


def get_stats() -> dict:
    """대시보드 통계를 조회합니다."""
    with SessionLocal() as db:
        run = db.query(AnalysisRun).order_by(AnalysisRun.id.desc()).first()
        if not run:
            return {"total_issues": 0, "high": 0, "medium": 0, "low": 0,
                    "patches_generated": 0, "patches_verified": 0}
        return {
            "total_issues": run.total_issues,
            "high": run.high_count,
            "medium": run.medium_count,
            "low": run.low_count,
            "patches_generated": run.patches_generated,
            "patches_verified": run.patches_verified,
            "duration_seconds": run.duration_seconds,
            "session_id": run.session_id,
            "total_sessions": db.query(AnalysisRun).count(),
        }


def get_vulnerabilities(severity: str = None, tool: str = None, file_path: str = None) -> list[dict]:
    """취약점 목록을 조회합니다."""
    with SessionLocal() as db:
        # 최신 분석의 취약점만
        run = db.query(AnalysisRun).order_by(AnalysisRun.id.desc()).first()
        if not run:
            return []

        q = db.query(Vulnerability).filter_by(run_id=run.id)
        if severity:
            q = q.filter(Vulnerability.severity == severity.upper())
        if tool:
            q = q.filter(Vulnerability.tool == tool.lower())
        if file_path:
            q = q.filter(Vulnerability.file_path.contains(file_path))

        return [_vuln_to_dict(v) for v in q.all()]


def get_patches() -> list[dict]:
    """패치 목록을 조회합니다."""
    with SessionLocal() as db:
        run = db.query(AnalysisRun).order_by(AnalysisRun.id.desc()).first()
        if not run:
            return []

        vulns = db.query(Vulnerability).filter_by(run_id=run.id).all()
        result = []
        for v in vulns:
            for p in v.patches:
                result.append({
                    **_patch_to_dict(p),
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "rule_id": v.rule_id,
                    "severity": v.severity,
                    "title": v.title,
                    "original_code": v.function_code or v.code_snippet,
                })
        return result


# ============================================================
# 내부 헬퍼
# ============================================================

def _run_to_dict(db, run: AnalysisRun) -> dict:
    vulns = db.query(Vulnerability).filter_by(run_id=run.id).all()
    patches = []
    vuln_dicts = []
    for v in vulns:
        vuln_dicts.append(_vuln_to_dict(v))
        for p in v.patches:
            patches.append({
                **_patch_to_dict(p),
                "vulnerability_id": v.vuln_id,
            })

    return {
        "session_id": run.session_id,
        "repo": run.repo,
        "pr_number": run.pr_number,
        "commit_sha": run.commit_sha,
        "summary": {
            "total": run.total_issues,
            "high": run.high_count,
            "medium": run.medium_count,
            "low": run.low_count,
            "patches_generated": run.patches_generated,
            "patches_verified": run.patches_verified,
        },
        "vulnerabilities": vuln_dicts,
        "patches": patches,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "duration_seconds": run.duration_seconds,
    }


def _vuln_to_dict(v: Vulnerability) -> dict:
    return {
        "id": v.vuln_id,
        "tool": v.tool,
        "rule_id": v.rule_id,
        "severity": v.severity,
        "confidence": v.confidence,
        "title": v.title,
        "description": v.description,
        "cwe_id": v.cwe_id,
        "file_path": v.file_path,
        "line_number": v.line_number,
        "code_snippet": _safe_decrypt(v.code_snippet),
        "function_code": _safe_decrypt(v.function_code),
    }


def _patch_to_dict(p: Patch) -> dict:
    return {
        "fixed_code": _safe_decrypt(p.fixed_code),
        "explanation": p.explanation,
        "fix_type": p.fix_type,
        "status": p.status,
        "syntax_valid": p.syntax_valid,
        "test_passed": p.test_passed,
    }


def _safe_decrypt(text: str) -> str:
    """암호화된 텍스트면 복호화, 아니면 그대로 반환"""
    if not text:
        return ""
    try:
        return _encryptor.decrypt(text)
    except Exception:
        return text  # 암호화 안 된 데이터는 그대로


def _parse_dt(val) -> Optional[datetime]:
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    try:
        return datetime.fromisoformat(val)
    except (ValueError, TypeError):
        return None


def _normalize_status(status: str) -> str:
    """PatchStatus.VERIFIED → verified"""
    if "." in status:
        return status.split(".")[-1].lower()
    return status.lower()
