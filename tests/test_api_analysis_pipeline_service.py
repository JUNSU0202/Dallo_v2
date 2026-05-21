"""분석 파이프라인 서비스 모듈 단위 테스트 (tests/test_api_analysis_pipeline_service.py).

Wave 2-S: ``api/routers/analyze.py`` 에 들어 있던 분석 파이프라인/잡 오케스트레이션
로직을 ``api.services.analysis_pipeline`` 으로 분리한 서비스의 단위 테스트.

검증 대상:
  - 서비스 모듈은 FastAPI / api.server 를 import 하지 않는다.
  - ``make_job_id()`` 가 ``job_`` prefix + timestamp + suffix 셰이프를 가진다.
  - ``build_initial_job_meta`` / ``build_upload_job_meta`` 가 라우터가 만들던
    잡 메타와 동일한 키 셰이프를 반환한다 (회귀 차단).
  - ``execute_analysis_job`` 이 monkeypatched ``REPORTS_DIR`` 로 full_result.json 을
    쓰고, ``ReportGenerator.save_report`` 를 호출하며, jobs[job_id] 상태를
    completed 로 갱신한다.
  - ``execute_pipeline`` 예외는 jobs[job_id] 의 status=failed + error 키로
    흡수된다.
  - 라우터의 ``_run_analysis`` 가 서비스의 ``execute_analysis_job`` 으로 위임한다
    (라우터 본체에 자체 파이프라인 로직이 없음을 확인).
"""

from __future__ import annotations

import ast
import inspect
import json
import os
from datetime import datetime

import pytest


# ============================================================
# Import surface
# ============================================================

class TestServiceImportSurface:
    def _module_source(self) -> str:
        from api.services import analysis_pipeline as svc

        return inspect.getsource(svc)

    def test_service_module_does_not_import_api_server(self):
        tree = ast.parse(self._module_source())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name != "api.server", "api.server 직접 import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "api.server", "from api.server import 금지"

    def test_service_module_does_not_import_fastapi(self):
        """서비스는 HTTP 계층(FastAPI) 의존을 가지지 않아야 한다."""
        tree = ast.parse(self._module_source())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert not n.name.startswith("fastapi"), "fastapi import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("fastapi"), (
                    "fastapi from-import 금지"
                )


# ============================================================
# 잡 ID / 잡 메타 빌더
# ============================================================

class TestJobIdAndMetaBuilders:
    def test_make_job_id_shape(self):
        from api.services.analysis_pipeline import make_job_id

        job_id = make_job_id()
        assert isinstance(job_id, str)
        assert job_id.startswith("job_")
        # ``job_<YYYYmmdd>_<HHMMSS>_<6자hex>`` — strftime 포맷이 ``_`` 를 포함하므로
        # split 결과는 4개. suffix(6자hex) 만 길이 회귀를 확인한다.
        parts = job_id.split("_")
        assert len(parts) == 4, f"unexpected job_id shape: {job_id}"
        assert len(parts[1]) == 8, f"날짜 길이 회귀: {parts[1]}"
        assert len(parts[2]) == 6, f"시각 길이 회귀: {parts[2]}"
        assert len(parts[3]) == 6, f"suffix 길이 회귀: {parts[3]}"

    def test_make_job_id_is_unique(self):
        from api.services.analysis_pipeline import make_job_id

        ids = {make_job_id() for _ in range(20)}
        # uuid suffix 가 다르므로 모두 유니크
        assert len(ids) == 20

    def test_build_initial_job_meta_shape(self):
        from api.services.analysis_pipeline import build_initial_job_meta

        meta = build_initial_job_meta(
            job_id="job_abc", filename="x.py", code_length=10, use_llm=False,
        )
        for k in ("job_id", "status", "step", "filename", "code_length",
                  "use_llm", "created_at", "result", "error"):
            assert k in meta, f"잡 메타 키 누락: {k}"
        assert meta["job_id"] == "job_abc"
        assert meta["status"] == "queued"
        assert meta["filename"] == "x.py"
        assert meta["code_length"] == 10
        assert meta["use_llm"] is False
        assert meta["result"] is None
        assert meta["error"] is None

    def test_build_upload_job_meta_shape(self):
        from api.services.analysis_pipeline import build_upload_job_meta

        meta = build_upload_job_meta(job_id="job_up", filename="upload.py")
        for k in ("job_id", "status", "step", "filename",
                  "created_at", "result", "error"):
            assert k in meta, f"업로드 잡 메타 키 누락: {k}"
        assert meta["status"] == "queued"
        assert meta["filename"] == "upload.py"
        assert meta["result"] is None
        assert meta["error"] is None


# ============================================================
# Wave 4-T: fakeable clock seam
# ============================================================

class TestClockSeam:
    """``make_job_id`` / ``build_initial_job_meta`` / ``build_upload_job_meta`` 의
    ``datetime.now()`` 경계를 keyword-only ``now`` 인자로 fakeable 화한 회귀 가드.
    """

    def test_make_job_id_accepts_fixed_now(self):
        from api.services.analysis_pipeline import make_job_id

        fixed = datetime(2026, 1, 2, 3, 4, 5)
        jid = make_job_id(now=fixed)
        # ``job_<YYYYmmdd>_<HHMMSS>_<6hex>`` shape 보존, prefix 결정적
        assert jid.startswith("job_20260102_030405_"), (
            f"fixed now prefix 회귀: {jid}"
        )
        # suffix 길이만 회귀 검증 — uuid 6자 hex
        assert len(jid) == len("job_20260102_030405_") + 6

    def test_make_job_id_now_is_keyword_only(self):
        from api.services.analysis_pipeline import make_job_id

        sig = inspect.signature(make_job_id)
        assert "now" in sig.parameters, "make_job_id 에 now 인자가 없다"
        assert (
            sig.parameters["now"].kind is inspect.Parameter.KEYWORD_ONLY
        ), "now 는 keyword-only 이어야 한다"
        # positional 호출은 거부
        with pytest.raises(TypeError):
            make_job_id(datetime(2026, 1, 2, 3, 4, 5))  # type: ignore[misc]

    def test_make_job_id_with_fixed_now_keeps_unique_uuid_suffix(self):
        from api.services.analysis_pipeline import make_job_id

        fixed = datetime(2026, 1, 2, 3, 4, 5)
        ids = {make_job_id(now=fixed) for _ in range(20)}
        # 같은 ``now`` 에서도 uuid suffix 가 다르므로 모두 유니크
        assert len(ids) == 20

    def test_make_job_id_default_path_uses_module_datetime(self, monkeypatch):
        """``now`` 미주입 시 모듈 ``datetime.now()`` 가 그대로 사용된다.

        ``api.services.analysis_pipeline.datetime`` 을 fake 로 교체해 default
        경로가 여전히 module 레벨 import 를 통과함을 회귀 검증한다.
        """
        import api.services.analysis_pipeline as svc

        class _FakeDT:
            @staticmethod
            def now():
                return datetime(2026, 6, 7, 8, 9, 10)

        monkeypatch.setattr(svc, "datetime", _FakeDT)
        jid = svc.make_job_id()
        assert jid.startswith("job_20260607_080910_"), (
            f"default 경로 datetime.now 회귀: {jid}"
        )

    def test_build_initial_job_meta_uses_fixed_now(self):
        from api.services.analysis_pipeline import build_initial_job_meta

        fixed = datetime(2026, 1, 2, 3, 4, 5)
        meta = build_initial_job_meta(
            job_id="job_x", filename="a.py", code_length=1, use_llm=False,
            now=fixed,
        )
        assert meta["created_at"] == fixed.isoformat()

    def test_build_initial_job_meta_now_is_keyword_only(self):
        from api.services.analysis_pipeline import build_initial_job_meta

        sig = inspect.signature(build_initial_job_meta)
        assert "now" in sig.parameters
        assert (
            sig.parameters["now"].kind is inspect.Parameter.KEYWORD_ONLY
        ), "build_initial_job_meta 의 now 는 keyword-only 이어야 한다"

    def test_build_initial_job_meta_default_path_uses_module_datetime(
        self, monkeypatch,
    ):
        import api.services.analysis_pipeline as svc

        class _FakeDT:
            @staticmethod
            def now():
                return datetime(2026, 6, 7, 8, 9, 10)

        monkeypatch.setattr(svc, "datetime", _FakeDT)
        meta = svc.build_initial_job_meta(
            job_id="job_x", filename="a.py", code_length=1, use_llm=False,
        )
        assert meta["created_at"] == "2026-06-07T08:09:10"

    def test_build_upload_job_meta_uses_fixed_now(self):
        from api.services.analysis_pipeline import build_upload_job_meta

        fixed = datetime(2026, 1, 2, 3, 4, 5)
        meta = build_upload_job_meta(
            job_id="job_y", filename="b.py", now=fixed,
        )
        assert meta["created_at"] == fixed.isoformat()

    def test_build_upload_job_meta_now_is_keyword_only(self):
        from api.services.analysis_pipeline import build_upload_job_meta

        sig = inspect.signature(build_upload_job_meta)
        assert "now" in sig.parameters
        assert (
            sig.parameters["now"].kind is inspect.Parameter.KEYWORD_ONLY
        ), "build_upload_job_meta 의 now 는 keyword-only 이어야 한다"

    def test_build_upload_job_meta_default_path_uses_module_datetime(
        self, monkeypatch,
    ):
        import api.services.analysis_pipeline as svc

        class _FakeDT:
            @staticmethod
            def now():
                return datetime(2026, 6, 7, 8, 9, 10)

        monkeypatch.setattr(svc, "datetime", _FakeDT)
        meta = svc.build_upload_job_meta(job_id="job_y", filename="b.py")
        assert meta["created_at"] == "2026-06-07T08:09:10"


# ============================================================
# execute_analysis_job — 성공 경로
# ============================================================

class _FakePipelineResult:
    def __init__(self, *, language="python", llm_error=None, db_error=None,
                 result_data=None):
        self.language = language
        self.llm_error = llm_error
        self.db_error = db_error
        self.result_data = result_data or {
            "session_id": "fake-session",
            "summary": {"total": 0, "high": 0, "medium": 0, "low": 0,
                        "patches_generated": 0, "patches_verified": 0},
            "vulnerabilities": [],
            "patches": [],
        }


class _FakeReportGenerator:
    def __init__(self):
        self.calls = []

    def save_report(self, data, output_dir, fmt="both", include_deps=True):
        self.calls.append({"data": data, "output_dir": output_dir, "fmt": fmt})
        os.makedirs(output_dir, exist_ok=True)
        html = os.path.join(output_dir, "report.html")
        md = os.path.join(output_dir, "report.md")
        with open(html, "w", encoding="utf-8") as fh:
            fh.write("<html></html>")
        with open(md, "w", encoding="utf-8") as fm:
            fm.write("# fake")
        return {"html": html, "md": md}


@pytest.fixture
def isolated_reports_dir(tmp_path, monkeypatch):
    from api import result_sources

    tmp_reports = tmp_path / "reports"
    monkeypatch.setattr(result_sources, "REPORTS_DIR", str(tmp_reports))
    return tmp_reports


@pytest.fixture
def fake_pipeline(monkeypatch):
    """analyzer.pipeline.execute_pipeline 을 가짜로 교체.

    호출 인자를 캡처할 수 있도록 list 를 같이 반환한다.
    """
    captured: list[dict] = []
    fake_result = _FakePipelineResult()

    def _fake(*a, **kw):
        captured.append(kw)
        return fake_result

    import analyzer.pipeline as pipeline_mod
    monkeypatch.setattr(pipeline_mod, "execute_pipeline", _fake)
    return captured, fake_result


@pytest.fixture
def fake_report_gen(monkeypatch):
    fake = _FakeReportGenerator()

    class _Cls:
        def __init__(self):
            pass

        def save_report(self, *a, **kw):
            return fake.save_report(*a, **kw)

    import reports.report_generator as rg_mod
    monkeypatch.setattr(rg_mod, "ReportGenerator", _Cls)
    return fake


class TestExecuteAnalysisJobSuccess:
    def test_writes_full_result_to_monkeypatched_reports_dir(
        self, isolated_reports_dir, fake_pipeline, fake_report_gen,
    ):
        from api.services.analysis_pipeline import execute_analysis_job

        captured_calls, fake_result = fake_pipeline
        jobs = {"j1": {"job_id": "j1", "status": "queued", "step": "..."}}

        execute_analysis_job(
            jobs=jobs, job_id="j1", code="x=1\n", filename="x.py",
            use_llm=False, provider="gemini", model="gemini-2.0-flash-lite",
            multi_patch=False,
        )

        # full_result.json 이 monkeypatched 디렉터리로 저장됐는지
        full_path = isolated_reports_dir / "full_result.json"
        assert full_path.exists(), (
            f"full_result.json 가 REPORTS_DIR={isolated_reports_dir} 에 없음"
        )
        loaded = json.loads(full_path.read_text(encoding="utf-8"))
        assert loaded == fake_result.result_data

    def test_updates_job_state_to_completed(
        self, isolated_reports_dir, fake_pipeline, fake_report_gen,
    ):
        from api.services.analysis_pipeline import execute_analysis_job

        jobs = {"j1": {"job_id": "j1", "status": "queued", "step": "..."}}

        execute_analysis_job(
            jobs=jobs, job_id="j1", code="x=1\n", filename="x.py",
            use_llm=False, provider="gemini", model="gemini-2.0-flash-lite",
        )

        meta = jobs["j1"]
        assert meta["status"] == "completed"
        assert meta["step"] == "완료"
        assert meta["language"] == "python"
        assert meta["result"] is not None
        # report_files 는 download URL 형식으로 매핑되어야 한다
        assert "report_files" in meta
        for k, v in meta["report_files"].items():
            assert v.startswith("/api/report/download/"), (
                f"report 다운로드 URL 셰이프 회귀: {k}={v}"
            )

    def test_passes_pipeline_kwargs(
        self, isolated_reports_dir, fake_pipeline, fake_report_gen,
    ):
        from api.services.analysis_pipeline import execute_analysis_job

        captured_calls, _ = fake_pipeline
        jobs = {"j1": {"job_id": "j1", "status": "queued", "step": "..."}}

        execute_analysis_job(
            jobs=jobs, job_id="j1", code="x=1\n", filename="x.py",
            use_llm=True, provider="gemini", model="gemini-2.0-flash-lite",
            multi_patch=True,
        )

        assert len(captured_calls) == 1
        kwargs = captured_calls[0]
        assert kwargs["job_id"] == "j1"
        assert kwargs["code"] == "x=1\n"
        assert kwargs["filename"] == "x.py"
        assert kwargs["use_llm"] is True
        assert kwargs["multi_patch"] is True
        # 진행 콜백이 함께 전달되어야 한다 (라우터 inline 에 있던 동작)
        assert callable(kwargs.get("on_progress"))


# ============================================================
# execute_analysis_job — 실패 경로
# ============================================================

class TestExecuteAnalysisJobFailure:
    def test_pipeline_exception_recorded_in_job(
        self, isolated_reports_dir, monkeypatch,
    ):
        from api.services.analysis_pipeline import execute_analysis_job

        def _boom(*a, **kw):
            raise RuntimeError("pipeline exploded")

        import analyzer.pipeline as pipeline_mod
        monkeypatch.setattr(pipeline_mod, "execute_pipeline", _boom)

        jobs = {"j1": {"job_id": "j1", "status": "queued", "step": "..."}}

        execute_analysis_job(
            jobs=jobs, job_id="j1", code="x=1\n", filename="x.py",
            use_llm=False, provider="gemini", model="gemini-2.0-flash-lite",
        )

        meta = jobs["j1"]
        assert meta["status"] == "failed"
        assert "pipeline exploded" in meta["error"]
        assert "오류" in meta["step"]

    def test_report_gen_failure_does_not_break_completion(
        self, isolated_reports_dir, fake_pipeline, monkeypatch,
    ):
        """ReportGenerator 가 터져도 분석 자체는 completed 로 끝나야 한다."""
        from api.services.analysis_pipeline import execute_analysis_job

        class _BoomReportGen:
            def save_report(self, *a, **kw):
                raise RuntimeError("report gen failed")

        import reports.report_generator as rg_mod
        monkeypatch.setattr(rg_mod, "ReportGenerator", _BoomReportGen)

        jobs = {"j1": {"job_id": "j1", "status": "queued", "step": "..."}}
        execute_analysis_job(
            jobs=jobs, job_id="j1", code="x=1\n", filename="x.py",
            use_llm=False, provider="gemini", model="gemini-2.0-flash-lite",
        )
        meta = jobs["j1"]
        assert meta["status"] == "completed"
        assert "report_error" in meta
        assert "report gen failed" in meta["report_error"]


# ============================================================
# 라우터 위임 검증 — _run_analysis 가 서비스로 위임
# ============================================================

class TestRouterDelegatesToService:
    def test_run_analysis_calls_execute_analysis_job(
        self, isolated_reports_dir, monkeypatch,
    ):
        """라우터의 ``_run_analysis`` 가 서비스 ``execute_analysis_job`` 을 호출한다.

        서비스 함수를 가짜로 교체하고 호출 인자를 캡처한다.
        """
        import api.routers.analyze as router_mod
        from api.services import analysis_pipeline as svc

        captured: list[dict] = []

        def _fake_execute(*, jobs, job_id, code, filename, use_llm,
                          provider, model, multi_patch=False,
                          llm_optimization=None):
            captured.append({
                "jobs_is": jobs, "job_id": job_id, "code": code,
                "filename": filename, "use_llm": use_llm,
                "provider": provider, "model": model,
                "multi_patch": multi_patch,
                "llm_optimization": llm_optimization,
            })

        monkeypatch.setattr(svc, "execute_analysis_job", _fake_execute)

        # 라우터의 analysis_jobs 를 새 dict 로 격리
        isolated_jobs = {"jX": {"job_id": "jX", "status": "queued"}}
        monkeypatch.setattr(router_mod, "analysis_jobs", isolated_jobs)

        router_mod._run_analysis(
            "jX", "code-here", "x.py", False, "gemini",
            "gemini-2.0-flash-lite", False,
        )

        assert len(captured) == 1
        call = captured[0]
        # 라우터는 자신의 analysis_jobs 글로벌을 그대로 서비스에 넘겨야 한다
        assert call["jobs_is"] is isolated_jobs
        assert call["job_id"] == "jX"
        assert call["code"] == "code-here"
        assert call["filename"] == "x.py"
        assert call["use_llm"] is False
        assert call["multi_patch"] is False

    def test_router_module_does_not_define_pipeline_body(self):
        """라우터의 ``_run_analysis`` 본체에 ``execute_pipeline`` 직접 호출이
        남아 있지 않아야 한다 — 서비스로 분리된 후의 회귀 차단.
        """
        import api.routers.analyze as router_mod

        src = inspect.getsource(router_mod)
        # 라우터 어디에도 execute_pipeline 직접 호출이 없어야 한다
        assert "execute_pipeline(" not in src, (
            "라우터에 execute_pipeline 직접 호출이 남아 있다 — "
            "서비스로 위임되지 않았음"
        )
        # ReportGenerator 직접 인스턴스화도 라우터에 남아 있으면 안 된다
        assert "ReportGenerator()" not in src, (
            "라우터에 ReportGenerator() 인스턴스화가 남아 있다 — 서비스 미위임"
        )


# ============================================================
# Wave 5-N — llm_audit_when_clean plumbing (service → pipeline)
# ============================================================


class TestServiceForwardsAuditWhenCleanToPipeline:
    """``execute_analysis_job`` 이 ``execute_pipeline`` 에 ``llm_audit_when_clean``
    을 그대로 전달하는지 검증. 기존 monkeypatch 표면은 그대로 유지된다.
    """

    def test_service_forwards_llm_audit_when_clean_true(
        self, isolated_reports_dir, fake_pipeline, fake_report_gen,
    ):
        from api.services.analysis_pipeline import execute_analysis_job

        captured_calls, _ = fake_pipeline
        jobs = {"j1": {"job_id": "j1", "status": "queued", "step": "..."}}

        execute_analysis_job(
            jobs=jobs, job_id="j1", code="x=1\n", filename="x.py",
            use_llm=True, provider="gemini", model="gemini-2.0-flash-lite",
            multi_patch=False, llm_audit_when_clean=True,
        )

        assert len(captured_calls) == 1
        kw = captured_calls[0]
        assert kw.get("llm_audit_when_clean") is True, (
            f"execute_analysis_job 이 llm_audit_when_clean=True 를 forwarding "
            f"하지 않음: {kw}"
        )

    def test_service_default_llm_audit_when_clean_is_false(
        self, isolated_reports_dir, fake_pipeline, fake_report_gen,
    ):
        """``llm_audit_when_clean`` 미지정 시 ``execute_pipeline`` 에
        ``False`` 가 전달되거나 키 자체가 부재하여 기존 동작이 보존되어야 한다.
        """
        from api.services.analysis_pipeline import execute_analysis_job

        captured_calls, _ = fake_pipeline
        jobs = {"j1": {"job_id": "j1", "status": "queued", "step": "..."}}

        execute_analysis_job(
            jobs=jobs, job_id="j1", code="x=1\n", filename="x.py",
            use_llm=True, provider="gemini", model="gemini-2.0-flash-lite",
        )

        assert len(captured_calls) == 1
        kw = captured_calls[0]
        # 미지정 시 ``False`` 또는 키 부재 — dict/True 가 새면 안 된다
        forwarded = kw.get("llm_audit_when_clean", False)
        assert forwarded is False, (
            f"omit 시 execute_pipeline 에 False 가 아닌 값 전달: {forwarded!r}"
        )


class TestRouterForwardsAuditWhenCleanToService:
    """라우터의 ``_run_analysis`` 가 ``llm_audit_when_clean`` 을 서비스로
    forwarding 하는지 검증.
    """

    def test_run_analysis_forwards_audit_when_clean_true(
        self, isolated_reports_dir, monkeypatch,
    ):
        import api.routers.analyze as router_mod
        from api.services import analysis_pipeline as svc

        captured: list[dict] = []

        def _fake_execute(**kwargs):
            captured.append(kwargs)

        monkeypatch.setattr(svc, "execute_analysis_job", _fake_execute)
        monkeypatch.setattr(router_mod, "analysis_jobs", {"jX": {}})

        router_mod._run_analysis(
            job_id="jX", code="c", filename="x.py", use_llm=True,
            provider="gemini", model="gemini-2.0-flash-lite",
            multi_patch=False, llm_audit_when_clean=True,
        )

        assert len(captured) == 1
        assert captured[0].get("llm_audit_when_clean") is True
