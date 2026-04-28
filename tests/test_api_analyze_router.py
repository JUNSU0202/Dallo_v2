"""분석/잡 라우터 테스트 (tests/test_api_analyze_router.py).

Wave 2-G: api/server.py 에서 분리된 분석 엔드포인트의 동작/응답 셰이프를
보존하기 위한 회귀 테스트.

핵심 원칙:
  - 절대 실제 분석 파이프라인이나 LLM/네트워크 호출이 발생하지 않도록
    api.routers.analyze 의 `_run_analysis` / `Thread` / `execute_pipeline` 을
    monkeypatch 한다.
  - Celery 토글(`_USE_CELERY`)은 메모리 폴백 경로를 강제하기 위해 False 로
    monkeypatch 한다 (Redis/실제 Celery 가 없는 CI 환경에서도 안정).
  - 기존 동작/JSON 셰이프/에러 메시지를 그대로 보존하는지 검증한다.
"""

from __future__ import annotations

import io
import os

import pytest
from fastapi.testclient import TestClient

from api.routers import analyze as analyze_router
from api.server import app


_AUTH_HEADERS = {"X-API-Key": "test-api-key"}
client = TestClient(app)


# ============================================================
# 공통 픽스처 — 백그라운드/Celery/파이프라인을 모두 차단
# ============================================================

@pytest.fixture
def memory_backend(monkeypatch):
    """Celery 비활성화 + 백그라운드 분석 함수를 노옵으로 강제.

    이 픽스처가 적용된 테스트에서는 절대 실제 파이프라인/LLM 호출이
    발생하지 않는다. 라우터는 메모리 폴백 경로를 타게 된다.
    """
    monkeypatch.setattr(analyze_router, "_USE_CELERY", False)
    monkeypatch.setattr(analyze_router, "_run_analysis", lambda *a, **kw: None)
    return None


@pytest.fixture
def isolated_jobs(monkeypatch):
    """analysis_jobs 메모리 상태를 빈 dict 로 격리.

    테스트 간 잡 상태가 누적되지 않도록 라우터 모듈의 module-level dict 자체를
    교체한다 (라우터는 모듈 글로벌을 참조하므로 monkeypatch.setattr 로 충분).
    """
    isolated = {}
    monkeypatch.setattr(analyze_router, "analysis_jobs", isolated)
    return isolated


# ============================================================
# 인증 보호
# ============================================================

class TestAnalyzeAuth:
    """헤더 없이 호출 시 인증 실패."""

    def test_post_analyze_requires_auth(self):
        r = client.post(
            "/api/analyze",
            json={"code": "print(1)\n", "filename": "x.py", "use_llm": False},
        )
        assert r.status_code in (401, 403)

    def test_get_analyze_status_requires_auth(self):
        r = client.get("/api/analyze/status/some-task-id")
        assert r.status_code in (401, 403)

    def test_get_analyze_job_requires_auth(self):
        r = client.get("/api/analyze/some-job-id")
        assert r.status_code in (401, 403)

    def test_post_analyze_file_requires_auth(self):
        r = client.post(
            "/api/analyze/file",
            files={"file": ("x.py", b"print(1)\n", "text/x-python")},
            data={"use_llm": "false"},
        )
        assert r.status_code in (401, 403)


# ============================================================
# POST /api/analyze — 메모리 폴백 응답 셰이프
# ============================================================

class TestStartAnalysisMemoryFallback:
    """Celery 비활성 상태에서의 즉시 응답 셰이프/사이드이펙트 회귀."""

    REQUIRED_TOP = {"job_id", "status", "message", "backend"}

    def test_memory_response_shape(self, memory_backend, isolated_jobs):
        payload = {
            "code": "print('hello')\n",
            "filename": "sample.py",
            "use_llm": False,
        }
        r = client.post("/api/analyze", json=payload, headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        data = r.json()

        assert set(data.keys()) >= self.REQUIRED_TOP
        assert data["backend"] == "memory"
        assert data["status"] == "queued"
        assert isinstance(data["job_id"], str) and data["job_id"].startswith("job_")
        assert "분석이 시작되었습니다" in data["message"]

    def test_memory_response_records_job_in_memory(self, memory_backend, isolated_jobs):
        """폴백 경로에서 analysis_jobs 에 잡 메타가 기록되어야 한다."""
        payload = {
            "code": "x=1\n",
            "filename": "tiny.py",
            "use_llm": False,
        }
        r = client.post("/api/analyze", json=payload, headers=_AUTH_HEADERS)
        assert r.status_code == 200
        job_id = r.json()["job_id"]

        # 라우터의 메모리 dict 에 동일 job_id 가 등록되어야 한다
        assert job_id in isolated_jobs
        meta = isolated_jobs[job_id]
        # 셰이프 회귀 차단 — 핵심 키 존재 검증
        for k in ("job_id", "status", "step", "filename", "code_length",
                  "use_llm", "created_at", "result", "error"):
            assert k in meta, f"잡 메타에 키 누락: {k}"
        assert meta["filename"] == "tiny.py"
        assert meta["code_length"] == len("x=1\n")
        assert meta["use_llm"] is False


# ============================================================
# GET /api/analyze/{job_id}
# ============================================================

class TestGetAnalysisStatus:
    """메모리 잡 / 미존재 잡 두 가지 경로."""

    def test_returns_in_memory_job_when_present(self, memory_backend, isolated_jobs):
        # 메모리에 잡을 직접 시드
        isolated_jobs["job_xxx"] = {
            "job_id": "job_xxx",
            "status": "completed",
            "step": "완료",
            "result": {"foo": "bar"},
        }
        r = client.get("/api/analyze/job_xxx", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["job_id"] == "job_xxx"
        assert data["status"] == "completed"
        assert data["step"] == "완료"
        assert data["result"] == {"foo": "bar"}

    def test_returns_job_not_found_when_celery_disabled(
        self, memory_backend, isolated_jobs,
    ):
        r = client.get("/api/analyze/nonexistent_job_id", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        assert r.json() == {"error": "Job not found"}


# ============================================================
# GET /api/analyze/status/{task_id} — Celery 비활성 응답
# ============================================================

class TestCeleryStatusDisabled:
    """Celery 가 활성화되지 않은 경우 기존 에러 셰이프를 그대로 반환."""

    def test_celery_disabled_error_shape(self, memory_backend):
        r = client.get("/api/analyze/status/any-task-id", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data == {"error": "Celery가 활성화되어 있지 않습니다."}


# ============================================================
# POST /api/analyze/file — 업로드 큐잉
# ============================================================

class TestAnalyzeFileUpload:
    """파일 업로드 시 Thread 가 시작되지 않고 잡 메타만 큐잉되는지 검증."""

    def test_upload_queues_job_without_running_pipeline(
        self, monkeypatch, isolated_jobs,
    ):
        # 실제 분석 파이프라인이 실행되지 않도록 차단
        monkeypatch.setattr(analyze_router, "_run_analysis", lambda *a, **kw: None)

        # Thread 도 즉시 동작을 차단 — start() 가 호출되어도 _run_analysis 가
        # 노옵이라 안전하지만, 명시적으로 Thread 자체를 가짜로 교체하여
        # 어떤 백그라운드 실행도 일어나지 않도록 강제한다.
        thread_starts: list[tuple] = []

        class _FakeThread:
            def __init__(self, target=None, args=(), kwargs=None):
                self._target = target
                self._args = args
                self._kwargs = kwargs or {}

            def start(self):
                thread_starts.append((self._target, self._args))

        monkeypatch.setattr(analyze_router, "Thread", _FakeThread)

        files = {"file": ("upload.py", io.BytesIO(b"a=1\n"), "text/x-python")}
        r = client.post(
            "/api/analyze/file",
            headers=_AUTH_HEADERS,
            files=files,
            data={"use_llm": "false"},
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert set(data.keys()) == {"job_id", "status"}
        assert data["status"] == "queued"
        job_id = data["job_id"]
        assert job_id.startswith("job_")

        # 잡 메타가 메모리에 기록되어야 한다
        assert job_id in isolated_jobs
        meta = isolated_jobs[job_id]
        assert meta["filename"] == "upload.py"
        assert meta["status"] == "queued"

        # Thread.start() 는 정확히 한 번 호출되어야 한다
        assert len(thread_starts) == 1
        target, args = thread_starts[0]
        # target 은 라우터의 _run_analysis (monkeypatch 된 노옵) 을 가리켜야 한다
        assert target is analyze_router._run_analysis
        # args 의 첫 인자는 job_id, 두번째는 코드 문자열
        assert args[0] == job_id
        assert args[1] == "a=1\n"
        assert args[2] == "upload.py"
        # use_llm=False 가 전달되어야 한다
        assert args[3] is False


# ============================================================
# 서비스 부트스트랩 스모크 — POST /api/analyze use_llm=False
# ============================================================

class TestServiceBootstrap:
    """app 임포트 + POST /api/analyze 메모리 폴백 200 — 라우터 분리 회귀 차단.

    pipeline / LLM 호출이 절대 발생하지 않도록 모듈 경계를 monkeypatch 한다.
    """

    def test_analyze_use_llm_false_smoke(self, monkeypatch):
        # 메모리 폴백 + 백그라운드 함수 노옵으로 절대 실제 파이프라인 미실행
        monkeypatch.setattr(analyze_router, "_USE_CELERY", False)
        monkeypatch.setattr(analyze_router, "_run_analysis", lambda *a, **kw: None)
        # 혹시 모를 실수로 _run_analysis 가 다시 lookup 되어도 차단되도록
        # execute_pipeline 자체도 폭탄으로 교체
        import analyzer.pipeline as pipeline_mod

        def _boom(*a, **kw):
            raise AssertionError("실제 파이프라인이 호출됐습니다 — 테스트 격리 실패")

        monkeypatch.setattr(pipeline_mod, "execute_pipeline", _boom)

        r = client.post(
            "/api/analyze",
            headers=_AUTH_HEADERS,
            json={
                "code": "print(1)\n",
                "filename": "smoke.py",
                "use_llm": False,
            },
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert sorted(data.keys()) == ["backend", "job_id", "message", "status"]
        assert data["backend"] == "memory"
        assert data["status"] == "queued"


# ============================================================
# 라우터 임포트 회귀 — api.server 미의존
# ============================================================

class TestRouterImportSurface:
    def test_module_does_not_import_api_server(self):
        import ast
        import inspect

        import api.routers.analyze as mod

        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name != "api.server", "api.server 직접 import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "api.server", "from api.server import 금지"

    def test_request_model_lives_in_router(self):
        assert hasattr(analyze_router, "AnalyzeRequest")
        assert hasattr(analyze_router, "_run_analysis")
        assert hasattr(analyze_router, "analysis_jobs")
        assert hasattr(analyze_router, "_USE_CELERY")


# ============================================================
# Wave 2-P — REPORTS_DIR 늦은 바인딩 (late binding)
# ============================================================

class TestReportsDirLateBinding:
    """``api.routers.analyze`` 가 ``REPORTS_DIR`` 을 모듈 임포트 시점에
    이름으로 끌어와 박제(early-bind)하지 않고, 호출 시점에
    ``api.result_sources.REPORTS_DIR`` 을 동적으로 참조해야 한다.

    회귀 시나리오:
      - 테스트가 ``monkeypatch.setattr(result_sources, 'REPORTS_DIR', tmp)`` 로
        디렉터리를 격리해도, ``analyze.py`` 가 임포트 시점에 박제한 원래
        REPORTS_DIR 로 ``full_result.json`` 을 쓰면 격리가 깨진다.
      - 늦은 바인딩으로 전환되면 monkeypatch 가 그대로 반영되어, 분석 결과
        파일 / 리포트 출력이 모두 tmp 디렉터리로 향한다.
    """

    def test_analyze_does_not_import_reports_dir_name_directly(self):
        """모듈 top-level 에 ``from api.result_sources import REPORTS_DIR`` 이
        없어야 한다 (이름 박제 금지). 모듈/패키지 import 는 허용 — 호출 시점에
        동적으로 ``result_sources.REPORTS_DIR`` 을 본다.
        """
        import ast
        import inspect

        import api.routers.analyze as mod

        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module == "api.result_sources":
                    for alias in node.names:
                        assert alias.name != "REPORTS_DIR", (
                            "REPORTS_DIR 를 from-import 로 박제하면 monkeypatch 가 "
                            "반영되지 않는다 — 모듈 참조로 늦게 바인딩하라"
                        )

    def test_run_analysis_writes_to_monkeypatched_reports_dir(
        self, tmp_path, monkeypatch, isolated_jobs,
    ):
        """``_run_analysis`` 가 ``result_sources.REPORTS_DIR`` 을 호출 시점에
        다시 읽어, monkeypatch 된 tmp 경로로 ``full_result.json`` 과 리포트를
        써야 한다.
        """
        from api import result_sources

        # 격리된 reports 디렉터리 — 실제 repo 의 reports/ 는 절대 건드리지 않는다.
        tmp_reports = tmp_path / "reports"
        # mkdir 은 _run_analysis 안의 os.makedirs(exist_ok=True) 가 처리하므로 생략
        monkeypatch.setattr(result_sources, "REPORTS_DIR", str(tmp_reports))

        # execute_pipeline 페이크 — 네트워크/LLM 절대 호출 금지
        fake_result_data = {
            "session_id": "fake-session",
            "summary": {"total": 0, "high": 0, "medium": 0, "low": 0,
                        "patches_generated": 0, "patches_verified": 0},
            "vulnerabilities": [],
            "patches": [],
        }

        class _FakePipelineResult:
            def __init__(self):
                self.language = "python"
                self.llm_error = None
                self.db_error = None
                self.result_data = fake_result_data

        def _fake_execute_pipeline(*a, **kw):
            return _FakePipelineResult()

        import analyzer.pipeline as pipeline_mod
        monkeypatch.setattr(pipeline_mod, "execute_pipeline", _fake_execute_pipeline)

        # ReportGenerator 페이크 — output_dir 을 캡처 + 가짜 파일 작성
        seen_output_dirs: list[str] = []

        class _FakeReportGenerator:
            def save_report(self, data, output_dir, fmt="both", include_deps=True):
                seen_output_dirs.append(output_dir)
                os.makedirs(output_dir, exist_ok=True)
                html_path = os.path.join(output_dir, "report.html")
                md_path = os.path.join(output_dir, "report.md")
                with open(html_path, "w", encoding="utf-8") as fh:
                    fh.write("<html></html>")
                with open(md_path, "w", encoding="utf-8") as fm:
                    fm.write("# fake")
                return {"html": html_path, "md": md_path}

        import reports.report_generator as rg_mod
        monkeypatch.setattr(rg_mod, "ReportGenerator", _FakeReportGenerator)

        # 호출 전, 기본 repo REPORTS_DIR 의 full_result.json 스냅샷.
        # (있다면 mtime/내용을 기억해, 호출 후 변하지 않았음을 확인한다.)
        default_full = os.path.join(
            result_sources.project_root(), "reports", "full_result.json",
        )
        default_existed = os.path.exists(default_full)
        default_pre_mtime = os.path.getmtime(default_full) if default_existed else None
        default_pre_bytes = (
            open(default_full, "rb").read() if default_existed else None
        )

        # 잡 메모리 시드
        job_id = "job_late_bind_test"
        isolated_jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "step": "대기",
            "filename": "x.py",
            "code_length": 0,
            "use_llm": False,
            "created_at": "2026-04-29T00:00:00",
            "result": None,
            "error": None,
        }

        # 호출 — 동기 실행
        analyze_router._run_analysis(
            job_id=job_id, code="print(1)\n", filename="x.py",
            use_llm=False, provider="gemini", model="gemini-2.0-flash-lite",
            multi_patch=False,
        )

        # 잡 상태가 completed 로 끝나야 한다 (실패 시 error 키에 단서가 남는다)
        meta = isolated_jobs[job_id]
        assert meta.get("error") is None, (
            f"_run_analysis 가 예외를 삼켰다: {meta.get('error')}"
        )
        assert meta["status"] == "completed", meta

        # full_result.json 이 monkeypatched tmp_reports 안에 있어야 한다
        full_path = tmp_reports / "full_result.json"
        assert full_path.exists(), (
            f"full_result.json 가 monkeypatched REPORTS_DIR 에 없음 — "
            f"early-bind REPORTS_DIR 사용 의심. tmp_reports={tmp_reports}"
        )
        import json as _json
        loaded = _json.loads(full_path.read_text(encoding="utf-8"))
        assert loaded == fake_result_data

        # ReportGenerator.save_report 가 monkeypatched 경로로 호출되어야 한다
        assert seen_output_dirs == [str(tmp_reports)], (
            f"ReportGenerator 가 잘못된 output_dir 로 호출됨: {seen_output_dirs}"
        )

        # 기본 repo reports 경로의 full_result.json 이 이번 호출로 인해
        # 변경되지 않았는지 확인. 호출 이전 스냅샷(존재 여부/mtime/바이트) 과
        # 비교하여 안전하게 검증한다 — 파일을 삭제하지 않는다.
        default_now_exists = os.path.exists(default_full)
        if default_existed:
            assert default_now_exists, (
                "호출 전 존재하던 기본 reports/full_result.json 이 사라졌다"
            )
            default_post_bytes = open(default_full, "rb").read()
            assert default_post_bytes == default_pre_bytes, (
                "기본 repo reports/full_result.json 의 내용이 이번 호출로 인해 변경됨 — "
                "monkeypatch 가 무시되었다 (early-bind REPORTS_DIR 사용 의심)"
            )
        else:
            assert not default_now_exists, (
                "호출 전 부재하던 기본 reports/full_result.json 이 새로 쓰임 — "
                "monkeypatch 가 무시되었다 (early-bind REPORTS_DIR 사용)"
            )
