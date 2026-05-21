"""Wave 5-N — ``execute_pipeline(llm_audit_when_clean=True)`` clean-audit 행동.

검증 대상:
  ``analyzer.pipeline.execute_pipeline`` 가 ``use_llm=True`` + 정적 분석
  결과 0건 + ``llm_audit_when_clean=True`` 일 때:

  1. ``_generate_clean_audit(code, filename, lang, provider, model)`` 헬퍼를
     호출하여 ``DalloAgent.audit_code`` 가 만든 audit dict 를 ``result_data
     ["llm_audit"]`` 에 부착한다.
  2. audit findings 를 ``_audit_findings_to_vulnerabilities(audit, filename,
     lang, source_code=...)`` 로 ``VulnerabilityReport`` 객체로 변환한다 —
     id 가 ``llm_audit_`` 로 시작하고, ``tool == "llm_audit"`` 이며,
     ``file_path == filename``, ``function_code == source_code`` 가 유지된다.
  3. 변환된 audit vuln 들이 ``_generate_patches`` 로 흘러간다 (Blue Team
     패치 생성) — ``provider`` / ``model`` / ``multi_patch`` / ``user_prompt``
     forwarding 은 기존과 동일.
  4. ``llm_optimization`` 이 supplied 된 경우 audit vuln 에도
     ``_apply_llm_optimization`` 을 적용하고, summary 는 ``result_data
     ["llm_optimization"]["clean_audit"]`` 에 보고된다. 미지정 시 top-level
     ``llm_optimization`` 키를 새로 만들지 않는다.
  5. audit 가 findings=[] 이면 ``llm_audit`` 키는 result 에 등장하지만
     vuln/patches 는 0건.
  6. ``llm_audit_when_clean=False`` 또는 ``use_llm=False`` 면 audit 자체가
     호출되지 않고 pre-Wave-5-N 동작이 보존된다.
  7. audit 호출이 실패하면 ``pipeline_result.llm_error`` / ``result_data
     ["llm_error"]`` 가 채워지지만 파이프라인 전체는 깨지지 않는다.

원칙
----
- 실제 LLM/Celery/Redis/외부 API 호출 0.
- monkeypatch 로 모든 외부 의존 (``_run_static_analysis``,
  ``_persist_to_db``, ``_validate_syntax``, ``_validate_security``,
  ``_generate_patches``, ``_generate_clean_audit``) 을 차단한다.
- 기존 ``execute_pipeline`` 호출 셰이프 / 응답 dict 키 셰이프는 보존된다.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.schemas import PatchStatus, PatchSuggestion


# ============================================================
# 더블 / 헬퍼
# ============================================================


def _audit_with_one_ssrf() -> dict:
    """단일 SSRF (CWE-918) finding 을 가진 audit dict."""
    return {
        "status": "suspicious",
        "summary": "SSRF 가능성 발견",
        "findings": [
            {
                "title": "Server-Side Request Forgery",
                "cwe_id": "CWE-918",
                "severity": "HIGH",
                "line_number": 12,
                "evidence": "requests.get(user_url)",
                "reason": "사용자 입력 URL 을 그대로 fetch",
                "recommendation": "URL 도메인 allowlist 적용",
            }
        ],
    }


def _audit_with_one_auth() -> dict:
    """단일 Auth Bypass (CWE-287) finding 을 가진 audit dict."""
    return {
        "status": "suspicious",
        "summary": "request-controlled identity",
        "findings": [
            {
                "title": "Authentication Bypass",
                "cwe_id": "CWE-287",
                "severity": "HIGH",
                "line_number": 22,
                "evidence": "user_id = request.args['uid']",
                "reason": "request-controlled identifier",
                "recommendation": "use authenticated session principal",
            }
        ],
    }


def _audit_clean_no_findings() -> dict:
    return {"status": "clean", "summary": "ok", "findings": []}


def _fake_patch(vuln_id: str) -> PatchSuggestion:
    return PatchSuggestion(
        vulnerability_id=vuln_id,
        fixed_code="# patched\n",
        explanation="fake patch",
        fix_type="recommended",
        status=PatchStatus.GENERATED,
    )


@pytest.fixture
def stub_pipeline_external(monkeypatch):
    """모든 외부 경계를 무력화 — 정적 분석은 빈 결과, 검증/저장은 no-op."""
    import analyzer.pipeline as pipeline_mod

    monkeypatch.setattr(
        pipeline_mod, "_run_static_analysis", lambda *a, **kw: [],
    )
    monkeypatch.setattr(
        pipeline_mod, "_extract_context", lambda vrs, fn: vrs,
    )
    monkeypatch.setattr(
        pipeline_mod, "_persist_to_db", lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        pipeline_mod, "_validate_syntax", lambda patches, lang: None,
    )
    monkeypatch.setattr(
        pipeline_mod, "_validate_security",
        lambda patches, vuln_reports, lang, filename: None,
    )


# ============================================================
# 1) audit ON + use_llm=True — findings → vuln(s) → patch(es)
# ============================================================


class TestCleanAuditConversion:
    def test_audit_finding_becomes_vuln_with_llm_audit_prefix_and_patched(
        self, stub_pipeline_external, monkeypatch,
    ):
        """clean-audit finding 1건이 ``llm_audit_`` prefix vuln 으로 변환되어
        ``_generate_patches`` 에 넘어가고 result 에 patch 1건이 남는다."""
        import analyzer.pipeline as pipeline_mod

        source = "def fetch(u):\n    return requests.get(u)\n"

        audit_calls: list[tuple] = []

        def _fake_audit(code, filename, lang, provider, model):
            audit_calls.append((code, filename, lang, provider, model))
            return _audit_with_one_ssrf(), None

        monkeypatch.setattr(pipeline_mod, "_generate_clean_audit", _fake_audit)

        captured_targets: list[list] = []

        def _fake_generate(targets, provider, model, multi_patch, **kw):
            captured_targets.append(list(targets))
            patches = [_fake_patch(t.id) for t in targets]
            return patches, None

        monkeypatch.setattr(pipeline_mod, "_generate_patches", _fake_generate)

        result = pipeline_mod.execute_pipeline(
            job_id="job-w5n-1",
            code=source,
            filename="svc.py",
            use_llm=True,
            provider="gemini",
            model="gemini-2.0-flash-lite",
            multi_patch=False,
            llm_audit_when_clean=True,
        )

        # audit 헬퍼가 정확한 인자로 정확히 1회 호출되었다
        assert len(audit_calls) == 1, (
            f"_generate_clean_audit 호출 횟수: {len(audit_calls)}"
        )
        code_arg, fname_arg, lang_arg, prov_arg, model_arg = audit_calls[0]
        assert code_arg == source
        assert fname_arg == "svc.py"
        assert lang_arg == "python"
        assert prov_arg == "gemini"
        assert model_arg == "gemini-2.0-flash-lite"

        # audit dict 가 결과에 부착된다
        assert "llm_audit" in result.result_data, (
            "result_data 에 llm_audit 키가 부재"
        )
        audit_dict = result.result_data["llm_audit"]
        assert audit_dict["status"] == "suspicious"
        assert len(audit_dict["findings"]) == 1

        # audit finding 1건이 vuln 으로 변환되어 _generate_patches 로 흘러갔다
        assert len(captured_targets) == 1, (
            "_generate_patches 가 정확히 1회 호출되어야 함"
        )
        targets = captured_targets[0]
        assert len(targets) == 1, (
            f"audit vuln 1건이 patch 대상이어야 함: {len(targets)}"
        )
        audit_vuln = targets[0]
        assert audit_vuln.id.startswith("llm_audit_"), (
            f"audit vuln id 는 'llm_audit_' 로 시작해야 함: {audit_vuln.id!r}"
        )
        assert audit_vuln.tool == "llm_audit"
        assert audit_vuln.file_path == "svc.py"
        # source_code 가 function_code 로 보존된다
        assert audit_vuln.function_code == source, (
            f"audit vuln 의 function_code 가 원본 코드와 다름: "
            f"{audit_vuln.function_code!r}"
        )
        # cwe / severity / line / evidence / recommendation 도 채워졌다
        assert audit_vuln.cwe_id == "CWE-918"
        assert audit_vuln.severity == "HIGH"
        assert audit_vuln.line_number == 12

        # result 에 1건의 vuln, 1건의 patch 가 남는다
        assert len(result.result_data["vulnerabilities"]) == 1, (
            f"result.vulnerabilities 회귀: "
            f"{len(result.result_data['vulnerabilities'])}"
        )
        assert len(result.result_data["patches"]) == 1, (
            f"result.patches 회귀: {len(result.result_data['patches'])}"
        )

    def test_red_blue_summary_blue_generated_at_least_one(
        self, stub_pipeline_external, monkeypatch,
    ):
        """clean-audit 후 결과 dict 로 build_red_blue_summary 를 돌리면
        ``blue_team.patches_generated >= 1`` 이다."""
        import analyzer.pipeline as pipeline_mod
        from shared.red_blue import build_red_blue_summary

        monkeypatch.setattr(
            pipeline_mod, "_generate_clean_audit",
            lambda *a, **kw: (_audit_with_one_auth(), None),
        )

        def _fake_generate(targets, provider, model, multi_patch, **kw):
            return [_fake_patch(t.id) for t in targets], None

        monkeypatch.setattr(pipeline_mod, "_generate_patches", _fake_generate)

        result = pipeline_mod.execute_pipeline(
            job_id="job-w5n-rb",
            code="def f():\n    pass\n",
            filename="x.py",
            use_llm=True,
            llm_audit_when_clean=True,
        )

        summary = build_red_blue_summary(
            result.result_data["vulnerabilities"],
            result.result_data["patches"],
        )
        assert summary["blue_team"]["patches_generated"] >= 1, (
            f"blue_team.patches_generated 회귀: {summary['blue_team']}"
        )


# ============================================================
# 2) audit OFF — 기존 zero-vuln/no-patch 셰이프 보존
# ============================================================


class TestCleanAuditDisabled:
    def test_when_audit_off_no_call_and_old_shape(
        self, stub_pipeline_external, monkeypatch,
    ):
        """``llm_audit_when_clean=False`` (default) + 정적 분석 0건 →
        audit 헬퍼는 호출되지 않고, patches/vulns 는 0건."""
        import analyzer.pipeline as pipeline_mod

        audit_calls: list = []

        def _fake_audit(*a, **kw):
            audit_calls.append((a, kw))
            return _audit_with_one_ssrf(), None

        monkeypatch.setattr(pipeline_mod, "_generate_clean_audit", _fake_audit)

        patch_calls: list = []

        def _fake_generate(targets, provider, model, multi_patch, **kw):
            patch_calls.append(list(targets))
            return [], None

        monkeypatch.setattr(pipeline_mod, "_generate_patches", _fake_generate)

        result = pipeline_mod.execute_pipeline(
            job_id="job-w5n-off",
            code="x = 1\n",
            filename="x.py",
            use_llm=True,
            llm_audit_when_clean=False,  # explicit off
        )

        assert audit_calls == [], (
            f"audit_when_clean=False 인데 _generate_clean_audit 가 호출됨: "
            f"{audit_calls}"
        )
        assert patch_calls == [], (
            "정적 분석 0건 + audit off → _generate_patches 미호출이어야 함"
        )
        assert "llm_audit" not in result.result_data, (
            "audit off 시 result_data 에 llm_audit 키가 등장하면 안 됨"
        )
        assert result.result_data["vulnerabilities"] == []
        assert result.result_data["patches"] == []

    def test_use_llm_false_does_not_run_audit(
        self, stub_pipeline_external, monkeypatch,
    ):
        """``use_llm=False`` 면 ``llm_audit_when_clean=True`` 라도 audit 미호출."""
        import analyzer.pipeline as pipeline_mod

        audit_calls: list = []

        def _fake_audit(*a, **kw):
            audit_calls.append((a, kw))
            return _audit_with_one_ssrf(), None

        monkeypatch.setattr(pipeline_mod, "_generate_clean_audit", _fake_audit)

        result = pipeline_mod.execute_pipeline(
            job_id="job-w5n-no-llm",
            code="x = 1\n",
            filename="x.py",
            use_llm=False,
            llm_audit_when_clean=True,
        )

        assert audit_calls == [], (
            f"use_llm=False 인데 audit 가 호출됨: {audit_calls}"
        )
        assert "llm_audit" not in result.result_data

    def test_static_findings_nonempty_skips_audit(
        self, stub_pipeline_external, monkeypatch,
    ):
        """정적 분석에서 1건 이상 발견되면 audit 은 호출되지 않는다."""
        import analyzer.pipeline as pipeline_mod
        from shared.schemas import VulnerabilityReport

        static_vuln = VulnerabilityReport(
            id="vuln_B608_10", tool="bandit", rule_id="B608",
            severity="HIGH", confidence="HIGH",
            title="SQL Injection", description="",
            file_path="x.py", line_number=10,
            code_snippet="q = f'...'", function_code="q = f'...'",
            cwe_id="CWE-89",
        )
        monkeypatch.setattr(
            pipeline_mod, "_run_static_analysis",
            lambda *a, **kw: [static_vuln],
        )

        audit_calls: list = []

        def _fake_audit(*a, **kw):
            audit_calls.append((a, kw))
            return _audit_with_one_ssrf(), None

        monkeypatch.setattr(pipeline_mod, "_generate_clean_audit", _fake_audit)

        def _fake_generate(targets, provider, model, multi_patch, **kw):
            return [], None

        monkeypatch.setattr(pipeline_mod, "_generate_patches", _fake_generate)

        pipeline_mod.execute_pipeline(
            job_id="job-w5n-not-clean",
            code="q = f'...'\n",
            filename="x.py",
            use_llm=True,
            llm_audit_when_clean=True,  # but static!=0 → no audit
        )

        assert audit_calls == [], (
            f"정적 0건이 아닌데 audit 가 호출됨: {audit_calls}"
        )


# ============================================================
# 3) llm_optimization supplied → audit vuln 도 최적화, summary는 clean_audit 아래
# ============================================================


class TestCleanAuditWithLLMOptimization:
    def test_optimization_summary_stored_under_clean_audit(
        self, stub_pipeline_external, monkeypatch,
    ):
        """``llm_optimization`` 이 supplied 되면 audit vuln 에도 최적화가
        적용되고, summary 는 ``result_data["llm_optimization"]["clean_audit"]``
        에 들어간다.
        """
        import analyzer.pipeline as pipeline_mod

        monkeypatch.setattr(
            pipeline_mod, "_generate_clean_audit",
            lambda *a, **kw: (_audit_with_one_ssrf(), None),
        )

        captured_targets: list[list] = []

        def _fake_generate(targets, provider, model, multi_patch, **kw):
            captured_targets.append(list(targets))
            return [_fake_patch(t.id) for t in targets], None

        monkeypatch.setattr(pipeline_mod, "_generate_patches", _fake_generate)

        opt = {
            "enabled": True,
            "cwe_scope": ["CWE-918"],
            "max_targets": 5,
            "max_context_chars": 0,
        }
        result = pipeline_mod.execute_pipeline(
            job_id="job-w5n-opt",
            code="def fetch(u):\n    return requests.get(u)\n",
            filename="svc.py",
            use_llm=True,
            llm_audit_when_clean=True,
            llm_optimization=opt,
        )

        # 1) audit vuln 이 patch targets 로 전달되었다
        assert len(captured_targets) == 1
        targets = captured_targets[0]
        assert len(targets) == 1
        assert targets[0].cwe_id == "CWE-918"
        assert targets[0].id.startswith("llm_audit_")

        # 2) summary 가 ``clean_audit`` 아래에 들어가 있다
        assert "llm_optimization" in result.result_data, (
            "supplied 시 top-level llm_optimization 키가 존재해야 한다"
        )
        opt_summary = result.result_data["llm_optimization"]
        assert "clean_audit" in opt_summary, (
            f"llm_optimization 에 clean_audit 키 부재: {opt_summary}"
        )
        clean_summary = opt_summary["clean_audit"]
        assert clean_summary["selected_count"] == 1
        assert "CWE-918" in clean_summary["scope"]["cwe"]

    def test_audit_vuln_visible_even_when_optimization_filters_to_zero_targets(
        self, stub_pipeline_external, monkeypatch,
    ):
        """``llm_optimization`` 이 audit vuln 을 0건으로 필터링해도, audit
        finding 은 ``result_data["vulnerabilities"]`` 에 그대로 보고되어야 한다.

        recipe 상 ``result_data["llm_audit"]["findings"]`` 와
        ``result_data["vulnerabilities"]`` 는 동등하게 사용자에게 노출되는
        취약점 정보이므로, 두 셰이프가 어긋나면 안 된다. patch 대상이 0건이라는
        이유로 vuln 자체를 누락시키는 것은 회귀.
        """
        import analyzer.pipeline as pipeline_mod

        monkeypatch.setattr(
            pipeline_mod, "_generate_clean_audit",
            lambda *a, **kw: (_audit_with_one_ssrf(), None),
        )

        patch_calls: list = []

        def _fake_generate(targets, provider, model, multi_patch, **kw):
            patch_calls.append(list(targets))
            return [_fake_patch(t.id) for t in targets], None

        monkeypatch.setattr(pipeline_mod, "_generate_patches", _fake_generate)

        # SSRF (CWE-918) finding 에 대해 매칭되지 않는 cwe_scope 를 준다
        # → optimize 결과 selected_count == 0 으로 patch 대상이 사라진다.
        opt = {
            "enabled": True,
            "cwe_scope": ["CWE-79"],  # XSS — SSRF 와 매칭되지 않음
            "max_targets": 5,
            "max_context_chars": 0,
        }

        result = pipeline_mod.execute_pipeline(
            job_id="job-w5n-opt-zero",
            code="def fetch(u):\n    return requests.get(u)\n",
            filename="svc.py",
            use_llm=True,
            llm_audit_when_clean=True,
            llm_optimization=opt,
        )

        # 1) audit dict 는 그대로 부착되어 있다.
        assert "llm_audit" in result.result_data, (
            "result_data 에 llm_audit 키가 부재"
        )
        assert len(result.result_data["llm_audit"]["findings"]) == 1

        # 2) patch 대상이 0건이라 _generate_patches 는 호출되지 않는다.
        assert patch_calls == [], (
            "audit_targets 가 0건이면 _generate_patches 는 호출되지 않아야 함: "
            f"{patch_calls}"
        )
        assert result.result_data["patches"] == [], (
            f"result.patches 회귀: {result.result_data['patches']}"
        )

        # 3) audit finding 은 여전히 vulnerabilities 에 노출되어야 한다.
        vulns = result.result_data["vulnerabilities"]
        assert len(vulns) == 1, (
            f"audit finding 은 patch 대상이 아니라도 vulnerabilities 에 "
            f"노출되어야 함: {len(vulns)}건"
        )
        assert vulns[0]["id"].startswith("llm_audit_"), (
            f"audit vuln id 는 'llm_audit_' 로 시작해야 함: {vulns[0]['id']!r}"
        )

        # 4) clean_audit 최적화 summary 의 selected_count == 0.
        clean_summary = (
            result.result_data["llm_optimization"]["clean_audit"]
        )
        assert clean_summary["selected_count"] == 0, (
            f"clean_audit summary 의 selected_count 는 0 이어야 함: "
            f"{clean_summary}"
        )

    def test_no_optimization_supplied_does_not_invent_key(
        self, stub_pipeline_external, monkeypatch,
    ):
        """``llm_optimization=None`` 시 audit path 가 작동해도 top-level
        ``llm_optimization`` 키를 새로 만들지 않는다."""
        import analyzer.pipeline as pipeline_mod

        monkeypatch.setattr(
            pipeline_mod, "_generate_clean_audit",
            lambda *a, **kw: (_audit_with_one_ssrf(), None),
        )
        monkeypatch.setattr(
            pipeline_mod, "_generate_patches",
            lambda targets, provider, model, multi_patch, **kw: (
                [_fake_patch(t.id) for t in targets], None,
            ),
        )

        result = pipeline_mod.execute_pipeline(
            job_id="job-w5n-no-opt",
            code="x = 1\n",
            filename="x.py",
            use_llm=True,
            llm_audit_when_clean=True,
            llm_optimization=None,
        )
        assert "llm_audit" in result.result_data
        assert "llm_optimization" not in result.result_data, (
            "omit 시 top-level llm_optimization 키가 등장하면 안 됨"
        )


# ============================================================
# 4) audit clean (findings=[]) — result 에 llm_audit 만, vuln/patch 0
# ============================================================


class TestCleanAuditNoFindings:
    def test_no_findings_shape(self, stub_pipeline_external, monkeypatch):
        import analyzer.pipeline as pipeline_mod

        monkeypatch.setattr(
            pipeline_mod, "_generate_clean_audit",
            lambda *a, **kw: (_audit_clean_no_findings(), None),
        )

        patch_calls: list = []

        def _fake_generate(targets, provider, model, multi_patch, **kw):
            patch_calls.append(list(targets))
            return [], None

        monkeypatch.setattr(pipeline_mod, "_generate_patches", _fake_generate)

        result = pipeline_mod.execute_pipeline(
            job_id="job-w5n-no-finding",
            code="x = 1\n",
            filename="x.py",
            use_llm=True,
            llm_audit_when_clean=True,
        )

        assert result.result_data.get("llm_audit", {}).get("status") == "clean"
        assert result.result_data["vulnerabilities"] == []
        assert result.result_data["patches"] == []
        assert patch_calls == [], (
            "findings 가 0건이면 _generate_patches 는 호출되지 않아야 함"
        )


# ============================================================
# 5) audit 호출 실패 — llm_error 채우고 파이프라인은 살아 있어야 함
# ============================================================


class TestCleanAuditFailureIsolation:
    def test_audit_error_sets_llm_error_and_keeps_shape(
        self, stub_pipeline_external, monkeypatch,
    ):
        """``_generate_clean_audit`` 가 에러 메시지를 돌려주면 llm_error 가
        세팅되고 파이프라인은 정상 종료한다."""
        import analyzer.pipeline as pipeline_mod

        monkeypatch.setattr(
            pipeline_mod, "_generate_clean_audit",
            lambda *a, **kw: ({}, "rate limit"),
        )

        result = pipeline_mod.execute_pipeline(
            job_id="job-w5n-err",
            code="x = 1\n",
            filename="x.py",
            use_llm=True,
            llm_audit_when_clean=True,
        )

        assert result.llm_error == "rate limit"
        assert result.result_data.get("llm_error") == "rate limit"
        # 파이프라인은 깨지지 않고 zero-vuln 셰이프 유지
        assert result.result_data["vulnerabilities"] == []
        assert result.result_data["patches"] == []


# ============================================================
# 6) user_prompt forwarding 으로의 회귀 차단
# ============================================================


class TestCleanAuditUserPromptForwarding:
    def test_user_prompt_forwarded_into_generate_patches(
        self, stub_pipeline_external, monkeypatch,
    ):
        """clean-audit 경로에서도 ``user_prompt`` 가 _generate_patches 로 그대로
        forwarding 되어야 한다 (Wave 5-M 동작 보존)."""
        import analyzer.pipeline as pipeline_mod

        monkeypatch.setattr(
            pipeline_mod, "_generate_clean_audit",
            lambda *a, **kw: (_audit_with_one_ssrf(), None),
        )

        captured_kwargs: list[dict] = []

        def _fake_generate(targets, provider, model, multi_patch, **kw):
            captured_kwargs.append(kw)
            return [], None

        monkeypatch.setattr(pipeline_mod, "_generate_patches", _fake_generate)

        pipeline_mod.execute_pipeline(
            job_id="job-w5n-up",
            code="x = 1\n",
            filename="x.py",
            use_llm=True,
            llm_audit_when_clean=True,
            user_prompt="prefer allowlist over blocklist",
        )

        assert len(captured_kwargs) == 1
        assert captured_kwargs[0].get("user_prompt") == (
            "prefer allowlist over blocklist"
        )


__all__: list[str] = []
