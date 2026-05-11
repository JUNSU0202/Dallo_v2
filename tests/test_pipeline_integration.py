"""
파이프라인 통합 테스트 (tests/test_pipeline_integration.py)

정적 분석 결과 → 중복 제거 → 위험도 산정 순서로 호출되는지 검증.
LLM 호출은 mock으로 대체.
"""

import inspect
import os
import sys
from datetime import datetime
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.schemas import VulnerabilityReport


def _make_vulns():
    """테스트용 취약점 목록 생성 — 중복 포함"""
    code = "query = f'SELECT * FROM users WHERE id = {user_id}'"
    return [
        VulnerabilityReport(
            id="vuln_B608_10", tool="bandit", rule_id="B608",
            severity="HIGH", confidence="HIGH",
            title="SQL Injection", description="SQL injection via f-string",
            file_path="test.py", line_number=10,
            code_snippet=code, function_code=code,
            cwe_id="CWE-89",
        ),
        VulnerabilityReport(
            id="vuln_B608_20", tool="bandit", rule_id="B608",
            severity="HIGH", confidence="HIGH",
            title="SQL Injection", description="SQL injection via f-string",
            file_path="test.py", line_number=20,
            code_snippet=code, function_code=code,
            cwe_id="CWE-89",
        ),
        VulnerabilityReport(
            id="vuln_B303_30", tool="bandit", rule_id="B303",
            severity="MEDIUM", confidence="HIGH",
            title="Weak Hash", description="Use of md5",
            file_path="test.py", line_number=30,
            code_snippet="hashlib.md5(data)", function_code="hashlib.md5(data)",
            cwe_id="CWE-328",
        ),
    ]


class TestPipelineOrder:
    """파이프라인이 정적 분석 → 중복 제거 → 위험도 산정 → LLM 순서로 동작하는지 검증"""

    def test_dedup_then_risk_then_llm(self):
        """중복 제거 → 위험도 산정 → LLM 대표만 전달"""
        from analyzer.deduplicator import deduplicate
        from analyzer.risk_scorer import score_vulnerabilities

        vulns = _make_vulns()

        # Step 1: 중복 제거
        dedup_result = deduplicate(vulns)
        for v in vulns:
            v.duplicate_group_id = dedup_result.group_map.get(v.id, "")
        llm_targets = dedup_result.representatives

        # 동일 rule_id + 동일 코드 → 2개가 1개로 합쳐져야 함
        assert len(llm_targets) == 2  # B608 대표 1 + B303 1
        assert dedup_result.total_deduplicated == 1  # B608 중복 1개 제거

        # Step 2: 위험도 산정
        score_vulnerabilities(vulns)

        # SQL Injection(CWE-89)은 critical, Weak Hash(CWE-328)는 medium
        b608_vuln = next(v for v in vulns if v.rule_id == "B608")
        b303_vuln = next(v for v in vulns if v.rule_id == "B303")
        assert b608_vuln.risk_level == "critical"
        assert b303_vuln.risk_level == "medium"

        # Step 3: LLM에는 대표만 전달 (2건, 원래 3건)
        assert len(llm_targets) < len(vulns)

    def test_duplicate_group_id_assigned(self):
        """중복 그룹 ID가 모든 취약점에 부여되는지 검증"""
        from analyzer.deduplicator import deduplicate

        vulns = _make_vulns()
        dedup_result = deduplicate(vulns)
        for v in vulns:
            v.duplicate_group_id = dedup_result.group_map.get(v.id, "")

        # 모든 취약점에 그룹 ID 할당됨
        for v in vulns:
            assert v.duplicate_group_id != "", f"{v.id}에 그룹 ID 미할당"

        # B608 2개는 같은 그룹
        b608_vulns = [v for v in vulns if v.rule_id == "B608"]
        assert b608_vulns[0].duplicate_group_id == b608_vulns[1].duplicate_group_id

        # B303은 다른 그룹
        b303_vuln = next(v for v in vulns if v.rule_id == "B303")
        assert b303_vuln.duplicate_group_id != b608_vulns[0].duplicate_group_id

    def test_risk_score_persists_on_schema(self):
        """schemas.py의 risk_level, cvss_score 필드가 실제로 채워지는지 검증"""
        from analyzer.risk_scorer import score_vulnerabilities

        vulns = _make_vulns()
        score_vulnerabilities(vulns)

        for v in vulns:
            assert v.risk_level in ("critical", "high", "medium", "low"), \
                f"{v.id}: risk_level={v.risk_level}"
            assert 0 < v.cvss_score <= 10.0, \
                f"{v.id}: cvss_score={v.cvss_score}"

    def test_empty_vulns_no_error(self):
        """취약점 0건이어도 에러 없이 동작"""
        from analyzer.deduplicator import deduplicate
        from analyzer.risk_scorer import score_vulnerabilities

        result = deduplicate([])
        assert len(result.representatives) == 0

        score_vulnerabilities([])  # no error


# ============================================================
# Wave 4-U: _build_result fakeable clock seam
# ============================================================

class TestBuildResultClockSeam:
    """``analyzer.pipeline._build_result`` 의 ``datetime.now()`` 경계를
    keyword-only ``now`` 인자로 fakeable 화한 회귀 가드.

    Wave 4-P (DB clock seam) / 4-T (analysis pipeline clock seam) 와 동일한
    패턴: ``now is None`` 일 때만 ``datetime.now()`` 를 호출 → 운영 동작 무변경,
    테스트는 ``now=fixed`` 로 ``completed_at`` 을 결정적으로 검증.
    """

    def _empty_args(self):
        """``_build_result`` 호출에 사용할 최소 인자 집합."""
        return dict(
            job_id="job_clock_seam",
            vuln_reports=[],
            patches=[],
            elapsed=1.23,
        )

    def test_build_result_uses_fixed_now(self):
        """``now=fixed`` 주입 시 session dict 의 ``completed_at`` 이
        ``fixed.isoformat()`` 으로 결정된다."""
        from analyzer.pipeline import _build_result

        fixed = datetime(2026, 1, 2, 3, 4, 5)
        result = _build_result(**self._empty_args(), now=fixed)

        assert result["completed_at"] == fixed.isoformat(), (
            f"fixed now 가 completed_at 에 반영되지 않음: {result['completed_at']}"
        )

    def test_build_result_now_is_keyword_only(self):
        """``now`` 는 keyword-only 이어야 한다 — positional 호출은 ``TypeError``."""
        from analyzer.pipeline import _build_result

        sig = inspect.signature(_build_result)
        assert "now" in sig.parameters, "_build_result 에 now 인자가 없다"
        assert (
            sig.parameters["now"].kind is inspect.Parameter.KEYWORD_ONLY
        ), "now 는 keyword-only 이어야 한다"

        fixed = datetime(2026, 1, 2, 3, 4, 5)
        # positional 호출은 거부되어야 한다
        with pytest.raises(TypeError):
            _build_result(
                "job_clock_seam", [], [], 1.23, fixed,  # type: ignore[misc]
            )

    def test_build_result_default_path_uses_module_datetime(self, monkeypatch):
        """``now`` 미주입 시 모듈 레벨 ``datetime.now()`` 가 그대로 사용된다.

        ``analyzer.pipeline.datetime`` 을 fake 로 교체해 default 경로가 여전히
        module-level import 를 통과함을 회귀 검증한다.
        """
        import analyzer.pipeline as pipeline_mod

        class _FakeDT:
            @staticmethod
            def now():
                return datetime(2026, 6, 7, 8, 9, 10)

        monkeypatch.setattr(pipeline_mod, "datetime", _FakeDT)
        result = pipeline_mod._build_result(**self._empty_args())

        assert result["completed_at"] == "2026-06-07T08:09:10", (
            f"default 경로 datetime.now 회귀: {result['completed_at']}"
        )

    def test_build_result_preserves_existing_keys_and_shape(self):
        """``now`` 주입 여부와 무관하게 session dict 의 키 셋과
        ``duration_seconds`` 셰이프가 보존된다."""
        from analyzer.pipeline import _build_result

        fixed = datetime(2026, 1, 2, 3, 4, 5)
        result = _build_result(**self._empty_args(), now=fixed)

        expected_keys = {
            "session_id", "repo", "pr_number", "commit_sha", "branch",
            "summary", "vulnerabilities", "patches",
            "started_at", "completed_at", "duration_seconds",
        }
        assert expected_keys.issubset(result.keys()), (
            f"session dict 키 회귀: 누락={expected_keys - set(result.keys())}"
        )
        # Wave 4-T 이전과 동일한 고정 필드들
        assert result["session_id"] == "job_clock_seam"
        assert result["repo"] == "dashboard-upload"
        assert result["pr_number"] == 0
        assert result["commit_sha"] == "direct-upload"
        # elapsed 가 round(..., 2) 로 그대로 전달되어야 한다
        assert result["duration_seconds"] == 1.23
        # 빈 입력 → summary total 0
        assert result["summary"]["total"] == 0
        assert result["vulnerabilities"] == []
        assert result["patches"] == []

    def test_build_result_isoformat_round_trip(self):
        """``completed_at`` 은 fixed ``now`` 의 ``isoformat()`` 과 정확히 동치이며,
        ``datetime.fromisoformat`` 으로 다시 원래 ``datetime`` 으로 round-trip 한다."""
        from analyzer.pipeline import _build_result

        fixed = datetime(2026, 12, 31, 23, 59, 58, 123456)
        result = _build_result(**self._empty_args(), now=fixed)

        assert result["completed_at"] == fixed.isoformat()
        # round-trip: 문자열 → datetime 으로 정확히 복원되어야 한다
        assert datetime.fromisoformat(result["completed_at"]) == fixed
