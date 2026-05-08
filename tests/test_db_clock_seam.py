"""DB clock/deprecation seam test (Wave 4-P).

``AnalysisRun.started_at`` / ``Vulnerability.detected_at`` / ``Patch.created_at``
세 컬럼이 SQLAlchemy ``default=datetime.utcnow`` 를 사용하는 동안에는 Python
3.12 의 ``datetime.utcnow()`` ``DeprecationWarning`` 이 매 INSERT 마다
발생한다. 이를 막기 위해 ``db/clock.py`` 를 도입하여 fakeable, 비-deprecated
경로(``datetime.now(timezone.utc).replace(tzinfo=None)``)로 교체한다.

본 테스트는:

- ``db.clock`` 어댑터의 형태(naive UTC, fakeable) 를 동결한다.
- 세 컬럼의 default 콜러블이 ``datetime.utcnow`` 가 아니라 ``clock.now``
  계열로 교체되었음을 ``save_analysis()`` 동작에서 ``DeprecationWarning``
  미발생으로 회귀 검증한다.
- 테스트가 fake clock 을 주입하면 세 컬럼의 자동 생성 시각이 그 고정
  datetime 으로 결정됨을 확인한다.
- 외부 시스템 / 시크릿 / 네트워크에 절대 접근하지 않는다.
"""

from __future__ import annotations

import os
import sys
import uuid
import warnings
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import clock
from db import service as db_service
from db.models import AnalysisRun, Patch, SessionLocal, Vulnerability


# ============================================================
# 합성 입력 — full_result.json 셰이프, 시간 필드는 의도적으로 비움
# ============================================================

def _synthetic_payload_without_times(session_id: str) -> dict:
    """``started_at`` / patch ``created_at`` 가 비어 있어 컬럼 default 가
    발화하도록 만드는 최소 페이로드. 실제 비밀/토큰성 값은 포함하지 않는다.
    """
    return {
        "session_id": session_id,
        "repo": "test/clock-seam",
        "pr_number": 1,
        "commit_sha": "deadbeef",
        "branch": "main",
        "summary": {
            "total": 1,
            "high": 1,
            "medium": 0,
            "low": 0,
            "patches_generated": 1,
            "patches_verified": 0,
        },
        "vulnerabilities": [
            {
                "id": "vuln_clock_1",
                "tool": "bandit",
                "rule_id": "B608",
                "severity": "HIGH",
                "confidence": "HIGH",
                "title": "synthetic",
                "description": "synthetic",
                "cwe_id": "CWE-89",
                "file_path": "x.py",
                "line_number": 1,
                "code_snippet": "",
                "function_code": "",
                # detected_at 의도적으로 컬럼 default 에 위임 (입력 키 없음)
            },
        ],
        "patches": [
            {
                "vulnerability_id": "vuln_clock_1",
                "fixed_code": "pass",
                "explanation": "",
                "fix_type": "recommended",
                "status": "pending",
                "syntax_valid": True,
                "test_passed": None,
                # created_at 의도적으로 누락 — 컬럼 default 가 발화해야 함
            },
        ],
        # started_at / completed_at 누락 — AnalysisRun.started_at default 가 발화
    }


def _cleanup_session(session_id: str) -> None:
    with SessionLocal() as db:
        existing = db.query(AnalysisRun).filter_by(session_id=session_id).first()
        if not existing:
            return
        for v in existing.vulnerabilities:
            for p in v.patches:
                db.delete(p)
            db.delete(v)
        db.delete(existing)
        db.commit()


@pytest.fixture(autouse=True)
def _restore_clock_after_test():
    """fake clock 을 주입하는 테스트가 누설되지 않도록 매 테스트 후 reset."""
    yield
    clock.reset_clock()


# ============================================================
# Test 1 — ``save_analysis()`` 가 utcnow DeprecationWarning 을 더 이상
#          유발하지 않는다 (RED→GREEN).
# ============================================================

def test_save_analysis_emits_no_utcnow_deprecation_warning():
    session_id = f"clock_seam_{uuid.uuid4().hex[:8]}"
    payload = _synthetic_payload_without_times(session_id)

    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            db_service.save_analysis(payload)

        utcnow_warnings = [
            w for w in caught
            if issubclass(w.category, DeprecationWarning)
            and "utcnow" in str(w.message)
        ]
        assert utcnow_warnings == [], (
            "save_analysis()가 datetime.utcnow DeprecationWarning을 유발했다: "
            + "; ".join(str(w.message) for w in utcnow_warnings)
        )
    finally:
        _cleanup_session(session_id)


# ============================================================
# Test 2 — fake clock 주입 시, 세 컬럼이 모두 그 고정 시각으로 채워진다.
# ============================================================

def test_fake_clock_injection_drives_all_three_default_columns():
    fixed = datetime(2024, 1, 2, 3, 4, 5)  # naive
    clock.set_clock(lambda: fixed)

    session_id = f"clock_seam_fake_{uuid.uuid4().hex[:8]}"
    payload = _synthetic_payload_without_times(session_id)

    try:
        db_service.save_analysis(payload)

        with SessionLocal() as db:
            run = db.query(AnalysisRun).filter_by(session_id=session_id).one()
            vulns = db.query(Vulnerability).filter_by(run_id=run.id).all()
            assert len(vulns) == 1
            patches = vulns[0].patches
            assert len(patches) == 1

            assert run.started_at == fixed, (
                f"AnalysisRun.started_at expected {fixed}, got {run.started_at}"
            )
            assert vulns[0].detected_at == fixed, (
                f"Vulnerability.detected_at expected {fixed}, got {vulns[0].detected_at}"
            )
            assert patches[0].created_at == fixed, (
                f"Patch.created_at expected {fixed}, got {patches[0].created_at}"
            )
    finally:
        _cleanup_session(session_id)


# ============================================================
# Test 3 — clock.utcnow_naive() / clock.now() 셰이프 보존:
#          naive datetime, isoformat() 에 ``+00:00`` 미부착.
# ============================================================

def test_clock_returns_naive_utc_without_offset_suffix():
    a = clock.utcnow_naive()
    b = clock.now()

    assert isinstance(a, datetime)
    assert isinstance(b, datetime)
    assert a.tzinfo is None, "utcnow_naive()는 naive(UTC) datetime이어야 한다"
    assert b.tzinfo is None, "now()는 기본적으로 naive datetime이어야 한다"
    assert "+00:00" not in a.isoformat()
    assert "+00:00" not in b.isoformat()
    assert "Z" not in a.isoformat()
    assert "Z" not in b.isoformat()


# ============================================================
# Test 4 — set_clock/reset_clock 는 now() 만 영향, utcnow_naive() 는
#          항상 실시간 wallclock 을 반환 (deprecation-free 경로 보장).
# ============================================================

def test_set_clock_only_affects_now_not_utcnow_naive():
    fixed = datetime(2030, 6, 7, 8, 9, 10)
    clock.set_clock(lambda: fixed)
    try:
        assert clock.now() == fixed
        live = clock.utcnow_naive()
        # utcnow_naive 는 fake 영향을 받지 않는 wallclock — 고정값과 다를 것
        assert live != fixed
        assert live.tzinfo is None
    finally:
        clock.reset_clock()

    # reset 이후 now() 는 다시 wallclock 으로 복귀
    after = clock.now()
    assert after.tzinfo is None
    assert after != fixed


# ============================================================
# Test 5 — utcnow_naive() 는 datetime.utcnow() 를 사용하지 않는다.
#          (DeprecationWarning 미발생을 직접 확인)
# ============================================================

def test_utcnow_naive_does_not_emit_deprecation_warning():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        clock.utcnow_naive()
        clock.now()

    utcnow_warnings = [
        w for w in caught
        if issubclass(w.category, DeprecationWarning)
        and "utcnow" in str(w.message)
    ]
    assert utcnow_warnings == []
