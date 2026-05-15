"""Wave 5-F — LLM optimization option 플러밍 TDD 테스트.

검증 대상:
  AnalyzeRequest -> api.routers.analyze -> api.services.analysis_pipeline
  -> api.tasks.run_analysis_task -> analyzer.pipeline.execute_pipeline
  -> shared.llm_optimization.optimize_llm_targets

원칙:
  - 절대 실제 LLM/Celery/Redis/외부 API 를 호출하지 않는다.
  - shared/schemas.py 변경 금지.
  - llm_optimization 미지정 시 기존 동작이 100% 보존되어야 한다 (None 전파).
  - llm_optimization 지정 시 cwe/cve/rule 필터 + max_targets cap 이 정확히
    LLM 입력에 적용되고, 결과 dict 에 ``llm_optimization`` summary 키가 추가된다.
  - 새 토큰/정책 (gateway/claude-sonnet/provider 정책) 은 도입하지 않는다.
"""

from __future__ import annotations

import ast
import inspect
import io

import pytest
from fastapi.testclient import TestClient

from api.routers import analyze as analyze_router
from api.server import app
from shared.schemas import VulnerabilityReport


_AUTH_HEADERS = {"X-API-Key": "test-api-key"}
client = TestClient(app)


def _make_two_vulns_distinct_cwe() -> list[VulnerabilityReport]:
    """SQLi (CWE-89, B608) 1건 + Weak Hash (CWE-328, B303) 1건."""
    return [
        VulnerabilityReport(
            id="vuln_B608_10", tool="bandit", rule_id="B608",
            severity="HIGH", confidence="HIGH",
            title="SQL Injection", description="SQL injection via f-string",
            file_path="t.py", line_number=10,
            code_snippet="q = f'SELECT * FROM u WHERE id={id}'",
            function_code="def x():\n    q = f'SELECT * FROM u WHERE id={id}'",
            cwe_id="CWE-89",
        ),
        VulnerabilityReport(
            id="vuln_B303_30", tool="bandit", rule_id="B303",
            severity="MEDIUM", confidence="HIGH",
            title="Weak Hash", description="Use of md5",
            file_path="t.py", line_number=30,
            code_snippet="hashlib.md5(b'x')",
            function_code="def y():\n    hashlib.md5(b'x')",
            cwe_id="CWE-328",
        ),
    ]


# ============================================================
# 1) AnalyzeRequest 모델 — optional llm_optimization 허용
# ============================================================


class TestAnalyzeRequestModel:
    """``AnalyzeRequest`` 가 nested ``llm_optimization`` 을 받아들이고,
    미지정 시 기본값이 ``None`` 이어야 한다 (기존 동작 보존)."""

    def test_omitted_llm_optimization_defaults_to_none(self):
        req = analyze_router.AnalyzeRequest(code="x=1", filename="x.py")
        # Pre-Wave-5-F 동작 보존: optimization 키가 없으면 attribute 도 None
        assert getattr(req, "llm_optimization", None) is None

    def test_full_llm_optimization_object_accepted(self):
        payload = {
            "code": "x=1",
            "filename": "x.py",
            "use_llm": True,
            "llm_optimization": {
                "enabled": True,
                "cve_scope": ["CVE-2024-0001"],
                "cwe_scope": ["SQLI"],
                "rule_scope": ["B608"],
                "max_targets": 3,
                "max_context_chars": 1200,
                "batch_enabled": True,
                "batch_size": 5,
            },
        }
        req = analyze_router.AnalyzeRequest(**payload)
        opt = req.llm_optimization
        assert opt is not None
        # 필드 노출 — pydantic 모델 또는 dict-like
        if hasattr(opt, "model_dump"):
            d = opt.model_dump()
        elif isinstance(opt, dict):
            d = opt
        else:
            d = dict(opt)
        assert d["enabled"] is True
        assert d["cwe_scope"] == ["SQLI"]
        assert d["rule_scope"] == ["B608"]
        assert d["cve_scope"] == ["CVE-2024-0001"]
        assert d["max_targets"] == 3
        assert d["max_context_chars"] == 1200
        assert d["batch_enabled"] is True
        assert d["batch_size"] == 5

    def test_empty_llm_optimization_object_accepted(self):
        """``{}`` 는 명시 opt-in. 모든 필드 default 가 채워져야 한다."""
        req = analyze_router.AnalyzeRequest(
            code="x=1", filename="x.py", use_llm=True,
            llm_optimization={},
        )
        opt = req.llm_optimization
        assert opt is not None


# ============================================================
# 2) 메모리 폴백 라우터 — _run_analysis 로 optimization 전달
# ============================================================


class TestMemoryFallbackForwardsOptimization:
    """메모리 폴백 경로에서 라우터가 ``_run_analysis`` 에 optimization 을
    그대로 전달하는지 검증. 응답 셰이프는 변경되지 않는다.
    """

    def test_memory_fallback_forwards_llm_optimization(self, monkeypatch):
        captured: list[dict] = []

        def _spy(*args, **kwargs):
            captured.append({"args": args, "kwargs": kwargs})

        monkeypatch.setattr(analyze_router, "_USE_CELERY", False)
        monkeypatch.setattr(analyze_router, "_run_analysis", _spy)
        monkeypatch.setattr(analyze_router, "analysis_jobs", {})

        payload = {
            "code": "x=1\n", "filename": "x.py", "use_llm": False,
            "llm_optimization": {
                "enabled": True, "cwe_scope": ["SQLI"],
                "max_targets": 2, "max_context_chars": 800,
            },
        }
        r = client.post("/api/analyze", json=payload, headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        data = r.json()
        # 응답 셰이프는 변하지 않아야 한다
        assert set(data.keys()) >= {"job_id", "status", "message", "backend"}
        assert data["backend"] == "memory"

        assert len(captured) == 1
        # _run_analysis 호출에 optimization 이 어떤 형태로든 전달되어야 한다
        call = captured[0]
        forwarded = None
        if "llm_optimization" in call["kwargs"]:
            forwarded = call["kwargs"]["llm_optimization"]
        else:
            # positional 폴백 — args 전체를 검사
            for a in call["args"]:
                if a is None:
                    continue
                # dict 또는 pydantic 모델 모두 허용
                if isinstance(a, dict) and "cwe_scope" in a:
                    forwarded = a
                    break
                if hasattr(a, "cwe_scope"):
                    forwarded = a
                    break
        assert forwarded is not None, (
            f"_run_analysis 가 llm_optimization 을 받지 못함: {call}"
        )

    def test_memory_fallback_forwards_none_when_omitted(self, monkeypatch):
        """payload 에 llm_optimization 이 없으면 ``None`` 또는 키 자체가
        ``_run_analysis`` 에 ``None`` 으로 전달되어야 한다."""
        captured: list[dict] = []

        def _spy(*args, **kwargs):
            captured.append({"args": args, "kwargs": kwargs})

        monkeypatch.setattr(analyze_router, "_USE_CELERY", False)
        monkeypatch.setattr(analyze_router, "_run_analysis", _spy)
        monkeypatch.setattr(analyze_router, "analysis_jobs", {})

        r = client.post(
            "/api/analyze",
            json={"code": "x=1\n", "filename": "x.py", "use_llm": False},
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 200, r.text
        assert len(captured) == 1
        call = captured[0]
        # 키워드든 positional 이든, optimization 자리는 None 이어야 한다
        forwarded = call["kwargs"].get("llm_optimization", "MISSING")
        if forwarded == "MISSING":
            # positional — args 안에 dict/pydantic 모델이 들어 있으면 안 됨
            offenders = [
                a for a in call["args"]
                if (isinstance(a, dict) and "cwe_scope" in a)
                or hasattr(a, "cwe_scope")
            ]
            assert offenders == [], (
                f"omit 시 optimization 이 새어 들어옴: {offenders}"
            )
        else:
            assert forwarded is None, (
                f"omit 시 llm_optimization 이 None 이 아님: {forwarded!r}"
            )


# ============================================================
# 3) Celery 경로 — delay 호출에 optimization payload 전달
# ============================================================


class _FakeTaskHandle:
    def __init__(self, id_: str):
        self.id = id_


class _FakeTask:
    def __init__(self):
        self.calls: list[dict] = []

    def delay(self, **kwargs):
        self.calls.append(kwargs)
        return _FakeTaskHandle(id_="fake-task-w5f")


class TestCeleryDelayForwardsOptimization:
    """Celery 경로에서 ``run_analysis_task.delay(...)`` 가 optimization
    payload (JSON 호환 dict) 를 함께 받는지 검증. Redis/Celery 미사용."""

    def _enable_fake_celery(self, monkeypatch, fake_task: _FakeTask):
        monkeypatch.setattr(analyze_router, "_USE_CELERY", True, raising=False)
        monkeypatch.setattr(analyze_router, "_celery", object(), raising=False)
        monkeypatch.setattr(
            analyze_router, "run_analysis_task", fake_task, raising=False,
        )
        monkeypatch.setattr(
            analyze_router, "_ensure_celery_initialized", lambda: True,
        )
        monkeypatch.setattr(analyze_router, "analysis_jobs", {})

    def test_delay_receives_optimization_payload(self, monkeypatch):
        fake = _FakeTask()
        self._enable_fake_celery(monkeypatch, fake)

        payload = {
            "code": "x=1\n", "filename": "x.py", "use_llm": True,
            "llm_optimization": {
                "enabled": True, "cwe_scope": ["SQLI"],
                "max_targets": 2,
            },
        }
        r = client.post("/api/analyze", json=payload, headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert len(fake.calls) == 1
        kwargs = fake.calls[0]
        # 기존 키들은 보존되어야 한다 (회귀 차단)
        assert kwargs["code"] == "x=1\n"
        assert kwargs["filename"] == "x.py"
        assert kwargs["use_llm"] is True
        # optimization 이 dict 형태로 전달되어야 한다 (Celery 직렬화 호환)
        assert "llm_optimization" in kwargs, (
            f"delay 호출에 llm_optimization 누락: {kwargs}"
        )
        opt = kwargs["llm_optimization"]
        assert isinstance(opt, dict), (
            f"delay 의 llm_optimization 은 JSON 직렬화 가능한 dict 여야 한다: "
            f"{type(opt)!r}"
        )
        assert opt["enabled"] is True
        assert opt["cwe_scope"] == ["SQLI"]
        assert opt["max_targets"] == 2

    def test_delay_omits_optimization_or_passes_none_when_unset(
        self, monkeypatch,
    ):
        """payload 에 llm_optimization 이 없으면 ``delay`` kwargs 의
        ``llm_optimization`` 은 키 부재 또는 ``None`` 이어야 한다 (기존 회귀
        차단). dict 가 들어가면 안 된다."""
        fake = _FakeTask()
        self._enable_fake_celery(monkeypatch, fake)

        r = client.post(
            "/api/analyze",
            json={"code": "x=1\n", "filename": "x.py", "use_llm": False},
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 200
        assert len(fake.calls) == 1
        kwargs = fake.calls[0]
        opt = kwargs.get("llm_optimization", None)
        assert opt is None, (
            f"omit 시 delay 의 llm_optimization 이 None 이 아님: {opt!r}"
        )


# ============================================================
# 4) api.tasks.run_analysis_task — execute_pipeline 으로 forwarding
# ============================================================


class TestCeleryTaskForwardsToPipeline:
    """``api.tasks.run_analysis_task`` 본체가 ``execute_pipeline`` 에
    ``llm_optimization`` 을 전달하는지 검증. Celery 브로커 미사용 — task
    함수 본체를 직접 호출한다."""

    def test_task_body_forwards_llm_optimization(self, monkeypatch):
        from api import tasks as tasks_mod

        captured_kwargs: list[dict] = []

        class _FakePipelineResult:
            def __init__(self):
                self.result_data = {"session_id": "fake"}
                self.language = "python"
                self.llm_error = None
                self.db_error = None

        def _fake_execute_pipeline(*args, **kwargs):
            captured_kwargs.append(kwargs)
            return _FakePipelineResult()

        import analyzer.pipeline as pipeline_mod
        monkeypatch.setattr(
            pipeline_mod, "execute_pipeline", _fake_execute_pipeline,
        )

        # Fake celery task self — request.id, update_state
        class _FakeRequest:
            id = "task-id-w5f"

        class _FakeSelf:
            request = _FakeRequest()

            def update_state(self, **kw):
                pass

        opt_payload = {
            "enabled": True, "cwe_scope": ["SQLI"], "max_targets": 1,
        }
        # Celery 의 ``@task(bind=True)`` 는 task 의 ``run`` 을 bound method 로
        # 노출한다. 본 테스트는 brokerless 로 task 본체만 검증하기 위해
        # ``run.__func__`` 의 raw function 에 ``self`` 를 직접 주입한다.
        task_obj = tasks_mod.run_analysis_task
        raw_fn = task_obj.run.__func__  # signature: (self, code, filename, ...)
        raw_fn(
            _FakeSelf(),
            code="x=1\n", filename="x.py", use_llm=True,
            provider="gemini", model="gemini-2.0-flash-lite",
            multi_patch=False,
            llm_optimization=opt_payload,
        )

        assert len(captured_kwargs) == 1
        kw = captured_kwargs[0]
        # llm_optimization 이 그대로 전달되어야 한다
        assert "llm_optimization" in kw, (
            f"run_analysis_task 본체가 execute_pipeline 에 "
            f"llm_optimization 을 전달하지 않음: {kw}"
        )
        assert kw["llm_optimization"] == opt_payload


# ============================================================
# 5) api.services.analysis_pipeline.execute_analysis_job — forwarding
# ============================================================


class TestServiceForwardsOptimizationToPipeline:
    """``execute_analysis_job`` 이 ``execute_pipeline`` 에 optimization 을
    그대로 전달하는지 검증. 기존 monkeypatch 표면은 그대로 유지된다.
    """

    def test_service_forwards_llm_optimization_kwarg(
        self, tmp_path, monkeypatch,
    ):
        from api import result_sources
        from api.services.analysis_pipeline import execute_analysis_job

        monkeypatch.setattr(
            result_sources, "REPORTS_DIR", str(tmp_path / "reports"),
        )

        captured: list[dict] = []

        class _FakePipelineResult:
            def __init__(self):
                self.language = "python"
                self.llm_error = None
                self.db_error = None
                self.result_data = {
                    "session_id": "j1",
                    "summary": {"total": 0, "high": 0, "medium": 0, "low": 0,
                                "patches_generated": 0, "patches_verified": 0},
                    "vulnerabilities": [],
                    "patches": [],
                }

        def _fake(*a, **kw):
            captured.append(kw)
            return _FakePipelineResult()

        import analyzer.pipeline as pipeline_mod
        monkeypatch.setattr(pipeline_mod, "execute_pipeline", _fake)

        # ReportGenerator 도 차단 — 보안/리소스 격리
        class _FakeReportGen:
            def save_report(self, *a, **kw):
                return {}

        import reports.report_generator as rg_mod
        monkeypatch.setattr(rg_mod, "ReportGenerator", _FakeReportGen)

        opt_payload = {"enabled": True, "cwe_scope": ["SQLI"], "max_targets": 2}
        jobs = {"j1": {"job_id": "j1", "status": "queued", "step": "..."}}
        execute_analysis_job(
            jobs=jobs, job_id="j1", code="x=1\n", filename="x.py",
            use_llm=True, provider="gemini", model="gemini-2.0-flash-lite",
            multi_patch=False, llm_optimization=opt_payload,
        )

        assert len(captured) == 1
        kw = captured[0]
        assert "llm_optimization" in kw, (
            f"execute_analysis_job 이 llm_optimization 을 forwarding 하지 않음: {kw}"
        )
        assert kw["llm_optimization"] == opt_payload

    def test_service_default_llm_optimization_is_none(
        self, tmp_path, monkeypatch,
    ):
        """``llm_optimization`` 미지정 시 ``execute_pipeline`` 에 None 이
        전달되어 기존 동작이 보존되어야 한다."""
        from api import result_sources
        from api.services.analysis_pipeline import execute_analysis_job

        monkeypatch.setattr(
            result_sources, "REPORTS_DIR", str(tmp_path / "reports"),
        )

        captured: list[dict] = []

        class _FakePipelineResult:
            def __init__(self):
                self.language = "python"
                self.llm_error = None
                self.db_error = None
                self.result_data = {
                    "session_id": "j1", "summary": {"total": 0, "high": 0,
                    "medium": 0, "low": 0, "patches_generated": 0,
                    "patches_verified": 0},
                    "vulnerabilities": [], "patches": [],
                }

        def _fake(*a, **kw):
            captured.append(kw)
            return _FakePipelineResult()

        import analyzer.pipeline as pipeline_mod
        monkeypatch.setattr(pipeline_mod, "execute_pipeline", _fake)

        class _FakeReportGen:
            def save_report(self, *a, **kw):
                return {}

        import reports.report_generator as rg_mod
        monkeypatch.setattr(rg_mod, "ReportGenerator", _FakeReportGen)

        jobs = {"j1": {"job_id": "j1", "status": "queued", "step": "..."}}
        execute_analysis_job(
            jobs=jobs, job_id="j1", code="x=1\n", filename="x.py",
            use_llm=True, provider="gemini", model="gemini-2.0-flash-lite",
        )
        assert len(captured) == 1
        kw = captured[0]
        # 미지정 시 None 으로 전달 (또는 키 부재 → kwargs.get 으로 None)
        assert kw.get("llm_optimization") is None, (
            f"omit 시 execute_pipeline 에 None 이 아닌 값 전달: "
            f"{kw.get('llm_optimization')!r}"
        )


# ============================================================
# 6) analyzer.pipeline.execute_pipeline — 최적화 적용 (cwe filter + cap)
# ============================================================


class TestExecutePipelineAppliesOptimization:
    """``execute_pipeline`` 이 dedup 후, risk scoring 후, ``_generate_patches``
    호출 직전에 ``optimize_llm_targets`` 를 적용해 LLM 입력을 좁히는지 검증.

    스텁:
      - ``_run_static_analysis`` 가 두 vuln (CWE-89, CWE-328) 을 돌려준다.
      - ``_persist_to_db`` no-op.
      - ``_generate_patches`` 는 받은 targets 를 캡처하고 빈 patches 반환.
    """

    @pytest.fixture
    def stub_pipeline(self, monkeypatch):
        import analyzer.pipeline as pipeline_mod

        vulns = _make_two_vulns_distinct_cwe()
        monkeypatch.setattr(
            pipeline_mod, "_run_static_analysis", lambda *a, **kw: vulns,
        )
        monkeypatch.setattr(pipeline_mod, "_persist_to_db", lambda *a, **kw: None)
        # 문맥 추출은 원래 mutating in-place — 그대로 통과시킨다 (no-op stub).
        monkeypatch.setattr(
            pipeline_mod, "_extract_context", lambda vrs, fn: vrs,
        )

        captured_targets: list[list] = []

        def _fake_generate(targets, provider, model, multi_patch):
            captured_targets.append(list(targets))
            return [], None

        monkeypatch.setattr(pipeline_mod, "_generate_patches", _fake_generate)
        return captured_targets

    def test_optimization_filters_to_cwe_scope_and_caps(self, stub_pipeline):
        from analyzer.pipeline import execute_pipeline

        captured_targets = stub_pipeline

        opt = {
            "enabled": True,
            "cwe_scope": ["SQLI"],   # SCOPE_ALIASES → CWE-89
            "max_targets": 1,
            "max_context_chars": 0,  # trim 비활성화 (값 동치 검증 단순화)
        }

        result = execute_pipeline(
            job_id="job_w5f_filter",
            code="x=1\n",
            filename="x.py",
            use_llm=True,
            provider="gemini",
            model="gemini-2.0-flash-lite",
            multi_patch=False,
            llm_optimization=opt,
        )

        # _generate_patches 는 정확히 1번 호출되고, 1건만 받아야 한다 (CWE-89)
        assert len(captured_targets) == 1, (
            f"_generate_patches 호출 횟수 회귀: {len(captured_targets)}"
        )
        targets = captured_targets[0]
        assert len(targets) == 1, (
            f"cwe scope=SQLI + max_targets=1 → 1건이어야 함: {len(targets)}"
        )
        assert targets[0].cwe_id == "CWE-89", (
            f"필터 후 첫 target cwe_id 회귀: {targets[0].cwe_id!r}"
        )
        # 결과 dict 에 summary 가 추가되어야 한다 (key 존재 + scope 정규화 결과)
        assert "llm_optimization" in result.result_data, (
            "config 지정 시 result_data 에 ``llm_optimization`` 키가 추가되어야 한다"
        )
        summary = result.result_data["llm_optimization"]
        assert summary["enabled"] is True
        assert summary["cap_applied"] is False  # cap 전 1건 → cap 적용 안 됨
        assert summary["selected_count"] == 1
        assert "scope" in summary
        assert "CWE-89" in summary["scope"]["cwe"]

    def test_no_optimization_passes_dedup_targets_unchanged(
        self, stub_pipeline,
    ):
        """``llm_optimization=None`` 시 ``_generate_patches`` 는 dedup 결과
        (CWE-89, CWE-328 두 건) 를 그대로 받아야 한다."""
        from analyzer.pipeline import execute_pipeline

        captured_targets = stub_pipeline

        result = execute_pipeline(
            job_id="job_w5f_no_opt",
            code="x=1\n",
            filename="x.py",
            use_llm=True,
            provider="gemini",
            model="gemini-2.0-flash-lite",
            multi_patch=False,
            llm_optimization=None,
        )

        assert len(captured_targets) == 1
        targets = captured_targets[0]
        cwe_ids = sorted(t.cwe_id for t in targets)
        assert cwe_ids == ["CWE-328", "CWE-89"], (
            f"omit 시 dedup 원본 (2건) 이 그대로 전달되어야 함: {cwe_ids}"
        )
        # summary key 가 부재해야 한다 (additive only when supplied)
        assert "llm_optimization" not in result.result_data, (
            "omit 시 result_data 에 llm_optimization 키가 등장하면 안 됨"
        )

    def test_optimization_with_use_llm_false_skips_patch_generation(
        self, stub_pipeline,
    ):
        """use_llm=False 면 _generate_patches 는 호출되지 않아야 한다 — 기존
        동작 보존. 단 summary 는 (config 가 supplied 됐으므로) 결과에 포함된다."""
        from analyzer.pipeline import execute_pipeline

        captured_targets = stub_pipeline

        opt = {"enabled": True, "cwe_scope": ["SQLI"], "max_targets": 1}
        result = execute_pipeline(
            job_id="job_w5f_no_llm",
            code="x=1\n",
            filename="x.py",
            use_llm=False,
            provider="gemini",
            model="gemini-2.0-flash-lite",
            multi_patch=False,
            llm_optimization=opt,
        )

        # use_llm=False → patches 생성 단계 스킵
        assert len(captured_targets) == 0, (
            "use_llm=False 인데 _generate_patches 가 호출됨"
        )
        # summary 는 supplied 됐으므로 포함되어야 한다
        assert "llm_optimization" in result.result_data


# ============================================================
# 7) Import-surface / AST 가드
# ============================================================


class TestImportSurfaceGuards:
    """서비스 모듈은 FastAPI/api.server 미의존. shared/schemas.py 변경 금지.
    gateway/claude-sonnet/provider 정책 토큰 도입 금지.
    """

    def test_analysis_pipeline_service_does_not_import_fastapi_or_server(self):
        from api.services import analysis_pipeline as svc

        src = inspect.getsource(svc)
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert not n.name.startswith("fastapi"), (
                        "fastapi import 금지"
                    )
                    assert n.name != "api.server", "api.server import 금지"
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                assert not mod.startswith("fastapi"), "fastapi from-import 금지"
                assert mod != "api.server", "api.server from-import 금지"

    def test_analyzer_pipeline_does_not_import_fastapi_or_server(self):
        import analyzer.pipeline as mod

        src = inspect.getsource(mod)
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert not n.name.startswith("fastapi")
                    assert n.name != "api.server"
            elif isinstance(node, ast.ImportFrom):
                mod_name = node.module or ""
                assert not mod_name.startswith("fastapi")
                assert mod_name != "api.server"

    def test_no_gateway_or_claude_sonnet_or_provider_policy_tokens(self):
        """Wave 5-F 는 신규 LLM provider/policy 토큰을 도입하지 않는다."""
        targets = [
            "api/routers/analyze.py",
            "api/services/analysis_pipeline.py",
            "api/tasks.py",
            "analyzer/pipeline.py",
        ]
        import pathlib
        repo_root = pathlib.Path(__file__).resolve().parent.parent
        banned = ["gateway", "claude-sonnet", "LLM_PRIMARY_PROVIDER"]
        for rel in targets:
            text = (repo_root / rel).read_text(encoding="utf-8")
            for token in banned:
                assert token not in text, (
                    f"금지 토큰 {token!r} 가 {rel} 에 도입됨"
                )

    def test_shared_schemas_unchanged(self):
        """``shared/schemas.py`` 는 본 wave 의 어떤 변경도 받지 않는다 — 변경
        여부를 git diff 로 확인하기는 비싸므로, 본 테스트는 우리가 절대로
        추가하지 말아야 할 신규 필드 토큰 (``llm_optimization`` 추가 등) 이
        들어오지 않았는지를 가벼운 텍스트 가드로 확인한다.
        """
        import pathlib
        repo_root = pathlib.Path(__file__).resolve().parent.parent
        text = (repo_root / "shared" / "schemas.py").read_text(encoding="utf-8")
        # Wave 5-F 가 schemas.py 를 건드렸다면 보통 LLMOptimization 관련 식별자가
        # 추가되었을 가능성이 높다.
        for tok in ("LLMOptimization", "llm_optimization", "optimize_llm_targets"):
            assert tok not in text, (
                f"shared/schemas.py 에 Wave 5-F 토큰 {tok!r} 가 추가됨 — 변경 금지"
            )
