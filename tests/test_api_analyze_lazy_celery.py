"""Wave 2-K — api/routers/analyze.py 의 lazy Celery/Redis 회귀 테스트.

Hermes 발견:
  - 현 ``api/routers/analyze.py`` 가 모듈 top-level 에서 ``api.celery_app`` /
    ``api.tasks`` 를 임포트하고 ``_celery.connection_for_write().ensure_connection(
    max_retries=1, timeout=2)`` 까지 호출한다.
  - 즉, ``import api.routers.analyze`` 만으로 Redis 연결 시도가 발생한다.
    ('lazy import' 라 적힌 docstring 과 실제 동작이 어긋나 있음.)

본 테스트는 다음을 보장한다 (실패 시 RED):
  1. ``api.routers.analyze`` 의 모듈 top-level 소스에 ``from api.celery_app
     import …`` / ``from api.tasks import …`` / ``ensure_connection(`` 호출이
     남아 있지 않다.
  2. fresh subprocess 에서 ``api.routers.analyze`` 만 임포트해도
     ``api.celery_app`` / ``api.tasks`` 가 ``sys.modules`` 로 끌려 들어오지 않는다.
  3. ``_USE_CELERY=None`` (혹은 False) 인 기본 상태에서 lazy detector 가
     Celery 임포트에 실패하면 메모리 폴백(``backend=memory``) 이 유지된다.
  4. 가짜 Celery 객체를 모듈 글로벌에 주입하면 (`_USE_CELERY=True`,
     `_celery=fake`, `run_analysis_task=fake_task`) Celery 경로가 동작한다 —
     실제 Redis 가 없어도 통과해야 한다.
  5. ``GET /api/analyze/status/{task_id}`` 와 ``GET /api/analyze/{job_id}`` 는
     Celery 비활성/활성 양쪽에서 기존 응답 셰이프를 보존한다.

테스트 격리 원칙:
  - 절대 실제 Redis/Celery 에 접근하지 않는다.
  - subprocess 검사를 위해 ``CELERY_BROKER_URL`` 등 환경변수는 손대지 않는다 —
    부모 프로세스 환경을 그대로 상속하더라도, 모듈 임포트 자체에서 connection
    이 발생하지 않는 것이 본 테스트의 목적이다.
"""

from __future__ import annotations

import ast
import inspect
import subprocess
import sys
import textwrap

import pytest
from fastapi.testclient import TestClient


_AUTH_HEADERS = {"X-API-Key": "test-api-key"}


# ============================================================
# 1) 모듈 top-level 정적 가드
# ============================================================

class TestModuleTopLevelHasNoCeleryImport:
    """소스/AST 검사 — top-level 에 Celery 임포트/연결 시도 금지."""

    def test_top_level_does_not_import_api_celery_app(self):
        """try/with/if 블록을 포함한 모듈 top-level 어디에도 ``api.celery_app`` /
        ``api.tasks`` import 가 남아 있지 않아야 한다.

        함수 정의 / 클래스 정의 본체 안의 import 는 호출 시점 lazy import 이므로
        허용된다. 따라서 walker 는 FunctionDef / AsyncFunctionDef / ClassDef 의
        본체로는 들어가지 않는다.
        """
        import api.routers.analyze as mod

        src = inspect.getsource(mod)
        tree = ast.parse(src)

        def _iter_module_level(nodes):
            for n in nodes:
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue  # 함수/클래스 본체는 lazy 영역
                yield n
                # try/with/if 등 복합문 본체도 모듈 top-level 로 간주
                for field, value in ast.iter_fields(n):
                    if isinstance(value, list):
                        yield from _iter_module_level(
                            [v for v in value if isinstance(v, ast.AST)]
                        )

        banned = {"api.celery_app", "api.tasks"}
        for node in _iter_module_level(tree.body):
            if isinstance(node, ast.ImportFrom):
                assert node.module not in banned, (
                    f"모듈 top-level 에 from {node.module} import ... 가 남아 있음"
                )
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name not in banned, (
                        f"모듈 top-level 에 import {n.name} 이 남아 있음"
                    )

    def test_top_level_does_not_call_connection_for_write(self):
        """top-level expression 에서 ``ensure_connection`` 호출 금지."""
        import api.routers.analyze as mod

        src = inspect.getsource(mod)
        tree = ast.parse(src)

        for node in tree.body:
            # try/except 블록 내부의 top-level Redis 연결 시도도 금지
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    func = sub.func
                    name = None
                    if isinstance(func, ast.Attribute):
                        name = func.attr
                    elif isinstance(func, ast.Name):
                        name = func.id
                    if name in ("ensure_connection", "connection_for_write"):
                        # 단, 이 호출이 함수 정의 내부라면 OK — 함수 정의는
                        # tree.body 의 FunctionDef 노드 안에 있고 ast.walk 가
                        # 자식까지 따라간다. 따라서 node 가 FunctionDef 면
                        # 무시한다.
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            continue
                        pytest.fail(
                            f"모듈 top-level 에 {name}(...) 호출이 남아 있음 — "
                            "lazy 화 되어야 한다"
                        )


# ============================================================
# 2) fresh subprocess 임포트 — celery/api.tasks 가 로드되지 않아야 함
# ============================================================

class TestFreshImportDoesNotLoadCelery:
    """별도 프로세스에서 ``import api.routers.analyze`` 후 sys.modules 검사."""

    def test_subprocess_import_does_not_load_celery_app(self):
        script = textwrap.dedent(
            """
            import sys
            import api.routers.analyze  # noqa: F401
            loaded = {
                'api.celery_app': 'api.celery_app' in sys.modules,
                'api.tasks': 'api.tasks' in sys.modules,
            }
            print(repr(loaded))
            """
        )
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert proc.returncode == 0, (
            f"subprocess import 실패\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
        out = proc.stdout.strip().splitlines()[-1]
        loaded = ast.literal_eval(out)
        assert loaded["api.celery_app"] is False, (
            "fresh import 시 api.celery_app 이 sys.modules 에 로드됨 — "
            "여전히 모듈 top-level 임포트가 남아 있다"
        )
        assert loaded["api.tasks"] is False, (
            "fresh import 시 api.tasks 가 sys.modules 에 로드됨"
        )

    def test_subprocess_import_does_not_load_celery_lib_eagerly(self):
        """``celery`` 라이브러리 자체도 router 임포트만으로는 끌려오지 않아야 한다.

        (다른 모듈이 sys.modules 에 미리 셋업한 경우는 우리 책임이 아니지만,
        fresh subprocess 에서는 celery 가 로드되어 있지 않은 것이 옳다.)
        """
        script = textwrap.dedent(
            """
            import sys
            import api.routers.analyze  # noqa: F401
            print('celery' in sys.modules)
            """
        )
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert proc.returncode == 0
        last = proc.stdout.strip().splitlines()[-1]
        assert last == "False", (
            f"fresh import 시 celery 라이브러리가 로드됨 — top-level lazy 화 누락\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}"
        )


# ============================================================
# 3) lazy detector — Celery import 실패 → memory fallback
# ============================================================

class TestLazyDetectorMemoryFallback:
    """lazy detector 가 실패하면 메모리 폴백을 유지해야 한다."""

    def _make_client_with_failing_celery(self, monkeypatch):
        """``api.celery_app`` import 가 항상 실패하도록 환경을 세팅."""
        import api.routers.analyze as mod

        # 모듈 글로벌을 '미초기화' 상태로 되돌린다.
        monkeypatch.setattr(mod, "_USE_CELERY", None, raising=False)
        monkeypatch.setattr(mod, "_celery", None, raising=False)
        monkeypatch.setattr(mod, "run_analysis_task", None, raising=False)

        # 강제로 Celery 감지가 실패하게 한다 — 함수 자체를 패치하여 항상 False.
        # detector 는 모듈 안에 정의되어 있어야 한다 (구현 후 _ensure_celery_initialized).
        assert hasattr(mod, "_ensure_celery_initialized"), (
            "lazy detector ``_ensure_celery_initialized`` 가 노출되어 있어야 한다"
        )
        monkeypatch.setattr(mod, "_ensure_celery_initialized", lambda: False)

        # 백그라운드 분석은 노옵 — 절대 LLM/파이프라인 호출 금지
        monkeypatch.setattr(mod, "_run_analysis", lambda *a, **kw: None)

        # analysis_jobs 는 격리
        monkeypatch.setattr(mod, "analysis_jobs", {})

        from api.server import app
        return TestClient(app)

    def test_post_analyze_returns_memory_backend(self, monkeypatch):
        client = self._make_client_with_failing_celery(monkeypatch)
        r = client.post(
            "/api/analyze",
            headers=_AUTH_HEADERS,
            json={"code": "print(1)\n", "filename": "x.py", "use_llm": False},
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["backend"] == "memory"
        assert data["status"] == "queued"
        assert data["job_id"].startswith("job_")

    def test_celery_status_returns_disabled_message(self, monkeypatch):
        client = self._make_client_with_failing_celery(monkeypatch)
        r = client.get("/api/analyze/status/some-task-id", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        assert r.json() == {"error": "Celery가 활성화되어 있지 않습니다."}

    def test_get_analysis_status_returns_job_not_found(self, monkeypatch):
        client = self._make_client_with_failing_celery(monkeypatch)
        r = client.get("/api/analyze/nonexistent_job", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        assert r.json() == {"error": "Job not found"}


# ============================================================
# 4) Celery-enabled 경로 — 가짜 객체 주입으로 검증 (Redis 없음)
# ============================================================

class _FakeAsyncResult:
    """Celery AsyncResult 와 동일한 표면만 흉내내는 가짜."""

    def __init__(self, task_id, app=None):
        self.id = task_id
        self.state = "SUCCESS"
        self.result = {"status": "completed", "result": {"foo": "bar"}}

    @property
    def info(self):
        return {}


class _FakeTaskHandle:
    def __init__(self, id_: str):
        self.id = id_


class _FakeTask:
    def __init__(self):
        self.calls: list[dict] = []

    def delay(self, **kwargs):
        self.calls.append(kwargs)
        return _FakeTaskHandle(id_="fake-task-123")


class TestLazyDetectorCeleryEnabledPath:
    """``_USE_CELERY=True`` + 가짜 객체 주입 → Celery 경로 동작 검증."""

    def _enable_fake_celery(self, monkeypatch, fake_task: _FakeTask):
        import api.routers.analyze as mod

        # detector 를 우회하기 위해 이미 True 로 세팅 + 객체 주입
        monkeypatch.setattr(mod, "_USE_CELERY", True, raising=False)
        monkeypatch.setattr(mod, "_celery", object(), raising=False)
        monkeypatch.setattr(mod, "run_analysis_task", fake_task, raising=False)
        # detector 가 다시 호출되어도 기존 True 유지하도록 stub
        monkeypatch.setattr(mod, "_ensure_celery_initialized", lambda: True)

        # 메모리 잡 격리
        monkeypatch.setattr(mod, "analysis_jobs", {})

        from api.server import app
        return TestClient(app)

    def test_post_analyze_routes_to_fake_celery_task(self, monkeypatch):
        fake = _FakeTask()
        client = self._enable_fake_celery(monkeypatch, fake)

        r = client.post(
            "/api/analyze",
            headers=_AUTH_HEADERS,
            json={"code": "print(1)\n", "filename": "x.py", "use_llm": False},
        )
        assert r.status_code == 200, r.text
        data = r.json()
        # Celery 경로 응답 셰이프
        assert data["backend"] == "celery"
        assert data["status"] == "queued"
        assert data["job_id"] == "fake-task-123"
        assert "Celery" in data["message"]

        # delay 호출 인자 확인
        assert len(fake.calls) == 1
        kwargs = fake.calls[0]
        assert kwargs["code"] == "print(1)\n"
        assert kwargs["filename"] == "x.py"
        assert kwargs["use_llm"] is False

    def test_celery_status_uses_fake_async_result(self, monkeypatch):
        fake = _FakeTask()
        client = self._enable_fake_celery(monkeypatch, fake)

        # ``celery.result.AsyncResult`` 를 가짜로 교체 — 라우터는 함수 본체에서
        # ``from celery.result import AsyncResult`` 를 호출하므로 sys.modules
        # 의 모듈 객체 레벨에서 패치한다.
        import celery.result as cr_mod
        monkeypatch.setattr(cr_mod, "AsyncResult", _FakeAsyncResult)

        r = client.get("/api/analyze/status/abc", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["task_id"] == "abc"
        assert data["status"] == "SUCCESS"
        # SUCCESS 분기 — result 키가 채워져야 한다
        assert "result" in data


# ============================================================
# 5) 모듈 import 단계 진단 — _USE_CELERY 가 import-time Redis 체크에 의존하지 않음
# ============================================================

class TestImportTimeStateIsLazy:
    """모듈 import 직후 ``_USE_CELERY`` 가 미초기화 상태(None) 이어야 한다.

    구현은 ``_USE_CELERY`` 를 sentinel(None) 로 두고 lazy detector 가 첫 호출
    시 채우는 패턴을 사용한다. fresh subprocess 에서 attribute 가 None 이어야
    'import 시 Redis 체크가 발생하지 않는다' 는 회귀를 단언할 수 있다.
    """

    def test_subprocess_use_celery_is_none_after_import(self):
        script = textwrap.dedent(
            """
            import api.routers.analyze as mod
            print(repr(mod._USE_CELERY))
            """
        )
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert proc.returncode == 0, (
            f"subprocess 실패\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
        last = proc.stdout.strip().splitlines()[-1]
        assert last == "None", (
            f"fresh import 직후 _USE_CELERY 가 미초기화(None) 가 아니다: {last}"
        )
