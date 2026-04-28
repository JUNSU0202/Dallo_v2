"""Wave 3-A — ``api.services.celery_detector`` 서비스 단위 테스트.

본 서비스는 ``api/routers/analyze.py`` 에서 분리된 lazy Celery/Redis 가용성
감지기다. 다음을 검증한다:

  1. 모듈 import 만으로 ``api.celery_app`` / ``api.tasks`` / ``celery``
     라이브러리가 sys.modules 로 끌려오지 않는다 (lazy 보존).
  2. fresh 상태에서 ``is_celery_available()`` 첫 호출이 import 실패시
     ``False`` 를 캐시하고, 이후 호출은 추가 import 시도 없이 캐시 값을 반환.
  3. 가짜 ``api.celery_app`` / ``api.tasks`` 모듈을 sys.modules 에 주입하면
     첫 호출이 ``True`` 를 캐시하고 ``get_celery_app`` / ``get_run_analysis_task``
     에 가짜 객체가 노출된다.
  4. ``reset()`` 후 다음 호출은 다시 감지를 시도한다.
  5. ``set_state()`` 헬퍼가 캐시를 강제 세팅한다 — 후속 호출이 import 를
     시도하지 않는다.
  6. 라우터의 ``_ensure_celery_initialized`` 가 서비스 결과를 라우터 모듈
     글로벌(``_USE_CELERY``, ``_celery``, ``run_analysis_task``) 로 동기화한다.

테스트 격리:
  - 절대 실제 Redis/Celery 에 접근하지 않는다. ``api.celery_app`` /
    ``api.tasks`` 임포트는 sys.modules 직접 주입 또는 ImportError 강제로
    제어한다.
  - 각 테스트는 서비스 모듈 캐시를 ``reset()`` 으로 격리한다.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import textwrap

import pytest


@pytest.fixture(autouse=True)
def _reset_detector_state():
    """각 테스트 전후로 detector 캐시를 미초기화 상태로 초기화."""
    from api.services import celery_detector as cd
    cd.reset()
    yield
    cd.reset()


# ============================================================
# 1) lazy import 보존 — fresh subprocess 검사
# ============================================================

class TestServiceImportIsLazy:
    """서비스 모듈 import 만으로 Celery/Redis 부수효과가 발생하지 않아야 한다."""

    def test_subprocess_import_does_not_load_celery_app(self):
        script = textwrap.dedent(
            """
            import sys
            import api.services.celery_detector  # noqa: F401
            print(repr({
                'api.celery_app': 'api.celery_app' in sys.modules,
                'api.tasks': 'api.tasks' in sys.modules,
                'celery': 'celery' in sys.modules,
            }))
            """
        )
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=20,
        )
        assert proc.returncode == 0, (
            f"subprocess 실패\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
        last = proc.stdout.strip().splitlines()[-1]
        loaded = ast.literal_eval(last)
        assert loaded["api.celery_app"] is False
        assert loaded["api.tasks"] is False
        assert loaded["celery"] is False

    def test_initial_use_celery_is_none(self):
        from api.services import celery_detector as cd
        assert cd._USE_CELERY is None
        assert cd._celery_app is None
        assert cd._run_analysis_task is None


# ============================================================
# 2) is_celery_available — 실패 캐시 / 성공 캐시 / 재호출 idempotent
# ============================================================

class TestIsCeleryAvailableCaching:
    """첫 호출이 결과를 캐시하고, 이후 호출은 import 시도 없이 캐시값 반환."""

    def test_first_call_caches_false_when_import_fails(self, monkeypatch):
        """``api.celery_app`` import 가 실패하면 ``False`` 를 캐시한다."""
        from api.services import celery_detector as cd

        # 기존 sys.modules 에 등록된 ``api.celery_app`` / ``api.tasks`` 가 있더라도
        # 본 테스트에서는 import 가 실패하도록 강제한다.
        monkeypatch.delitem(sys.modules, "api.celery_app", raising=False)
        monkeypatch.delitem(sys.modules, "api.tasks", raising=False)

        # 실제 import 시 ImportError 가 나도록 sys.modules 에 None 을 박아둔다
        # (ImportError 와 동일하게 처리됨).
        monkeypatch.setitem(sys.modules, "api.celery_app", None)
        monkeypatch.setitem(sys.modules, "api.tasks", None)

        assert cd.is_celery_available() is False
        # 캐시 검증
        assert cd._USE_CELERY is False
        assert cd.get_celery_app() is None
        assert cd.get_run_analysis_task() is None

    def test_first_call_caches_true_with_fake_modules(self, monkeypatch):
        """가짜 ``api.celery_app`` / ``api.tasks`` 모듈 주입 → True 캐시."""
        import types

        from api.services import celery_detector as cd

        # 가짜 celery app — ensure_connection 이 성공하는 객체
        class _FakeConn:
            def ensure_connection(self, max_retries=1, timeout=2):
                return None

        class _FakeCeleryApp:
            def connection_for_write(self):
                return _FakeConn()

        fake_celery_app = _FakeCeleryApp()
        fake_task = object()

        celery_app_mod = types.ModuleType("api.celery_app")
        celery_app_mod.celery_app = fake_celery_app
        tasks_mod = types.ModuleType("api.tasks")
        tasks_mod.run_analysis_task = fake_task

        monkeypatch.setitem(sys.modules, "api.celery_app", celery_app_mod)
        monkeypatch.setitem(sys.modules, "api.tasks", tasks_mod)

        assert cd.is_celery_available() is True
        assert cd._USE_CELERY is True
        assert cd.get_celery_app() is fake_celery_app
        assert cd.get_run_analysis_task() is fake_task

    def test_cached_value_skips_reimport(self, monkeypatch):
        """캐시 후 재호출이 import 를 다시 시도하지 않는다."""
        from api.services import celery_detector as cd

        # 캐시를 False 로 강제
        cd.set_state(use_celery=False)

        # import 가 실제로 시도되면 폭탄을 터뜨릴 sentinel finder 주입
        boom_calls: list[str] = []

        class _BoomFinder:
            def find_spec(self, name, path=None, target=None):
                if name in ("api.celery_app", "api.tasks"):
                    boom_calls.append(name)
                return None

        finder = _BoomFinder()
        sys.meta_path.insert(0, finder)
        try:
            # 호출 자체는 캐시값을 반환해야 한다
            assert cd.is_celery_available() is False
            assert cd.is_celery_available() is False
        finally:
            sys.meta_path.remove(finder)

        # import 시도가 없어야 한다 — 캐시된 False 값을 즉시 반환
        assert boom_calls == [], (
            f"캐시 후에도 import 시도가 발생함: {boom_calls}"
        )

    def test_connection_failure_is_cached_as_false(self, monkeypatch):
        """``ensure_connection`` 이 예외를 던지면 False 로 캐시된다."""
        import types

        from api.services import celery_detector as cd

        class _FailConn:
            def ensure_connection(self, max_retries=1, timeout=2):
                raise ConnectionError("redis down")

        class _FakeCeleryApp:
            def connection_for_write(self):
                return _FailConn()

        celery_app_mod = types.ModuleType("api.celery_app")
        celery_app_mod.celery_app = _FakeCeleryApp()
        tasks_mod = types.ModuleType("api.tasks")
        tasks_mod.run_analysis_task = object()

        monkeypatch.setitem(sys.modules, "api.celery_app", celery_app_mod)
        monkeypatch.setitem(sys.modules, "api.tasks", tasks_mod)

        assert cd.is_celery_available() is False
        assert cd._celery_app is None
        assert cd._run_analysis_task is None


# ============================================================
# 3) reset / set_state 헬퍼
# ============================================================

class TestResetAndSetState:
    def test_reset_returns_to_uninitialized_state(self):
        from api.services import celery_detector as cd

        cd.set_state(use_celery=True, celery_app=object(), run_task=object())
        assert cd._USE_CELERY is True
        assert cd.get_celery_app() is not None

        cd.reset()
        assert cd._USE_CELERY is None
        assert cd.get_celery_app() is None
        assert cd.get_run_analysis_task() is None

    def test_set_state_makes_is_celery_available_skip_import(self, monkeypatch):
        """``set_state(use_celery=True, ...)`` 이후 ``is_celery_available()`` 가
        import 시도 없이 캐시값을 반환해야 한다.
        """
        from api.services import celery_detector as cd

        fake_app = object()
        fake_task = object()
        cd.set_state(use_celery=True, celery_app=fake_app, run_task=fake_task)

        # 강제로 import 가 발생하면 폭탄
        monkeypatch.setitem(sys.modules, "api.celery_app", None)
        monkeypatch.setitem(sys.modules, "api.tasks", None)

        # 캐시값 사용 — 예외 없이 True 반환
        assert cd.is_celery_available() is True
        assert cd.get_celery_app() is fake_app
        assert cd.get_run_analysis_task() is fake_task

    def test_set_state_to_none_allows_redetection(self, monkeypatch):
        """``set_state(use_celery=None)`` 이후 다시 감지를 시도한다."""
        from api.services import celery_detector as cd

        cd.set_state(use_celery=True, celery_app=object(), run_task=object())
        assert cd.is_celery_available() is True

        cd.set_state(use_celery=None)
        # import 실패 시나리오 강제
        monkeypatch.setitem(sys.modules, "api.celery_app", None)
        monkeypatch.setitem(sys.modules, "api.tasks", None)

        assert cd.is_celery_available() is False


# ============================================================
# 4) 라우터 ↔ 서비스 동기화
# ============================================================

class TestRouterSyncWithService:
    """``api.routers.analyze._ensure_celery_initialized`` 가 서비스에 위임하고
    라우터 모듈 글로벌을 동기화한다.
    """

    def test_router_ensure_calls_service_when_unset(self, monkeypatch):
        """라우터 ``_USE_CELERY`` 가 ``None`` 이면 서비스에 위임하고 결과를 캐시."""
        import api.routers.analyze as analyze_mod
        from api.services import celery_detector as cd

        monkeypatch.setattr(analyze_mod, "_USE_CELERY", None, raising=False)
        monkeypatch.setattr(analyze_mod, "_celery", None, raising=False)
        monkeypatch.setattr(analyze_mod, "run_analysis_task", None, raising=False)

        fake_app = object()
        fake_task = object()
        cd.set_state(use_celery=True, celery_app=fake_app, run_task=fake_task)

        result = analyze_mod._ensure_celery_initialized()
        assert result is True
        assert analyze_mod._USE_CELERY is True
        assert analyze_mod._celery is fake_app
        assert analyze_mod.run_analysis_task is fake_task

    def test_router_ensure_respects_router_level_override(self, monkeypatch):
        """라우터 ``_USE_CELERY`` 가 이미 True/False 면 서비스를 호출하지 않는다."""
        import api.routers.analyze as analyze_mod
        from api.services import celery_detector as cd

        # 서비스는 미초기화로 둔다
        cd.reset()

        # 라우터 글로벌만 직접 False 로 세팅 — 테스트가 monkeypatch 하던 패턴
        monkeypatch.setattr(analyze_mod, "_USE_CELERY", False, raising=False)

        # 서비스가 호출되면 폭탄
        def _boom():
            raise AssertionError("서비스 detector 가 호출되면 안 된다 (router override)")

        monkeypatch.setattr(cd, "is_celery_available", _boom)

        result = analyze_mod._ensure_celery_initialized()
        assert result is False

    def test_router_ensure_caches_failure_in_router_globals(self, monkeypatch):
        """서비스가 False 를 반환하면 라우터 ``_USE_CELERY`` 도 False 로 캐시."""
        import api.routers.analyze as analyze_mod
        from api.services import celery_detector as cd

        monkeypatch.setattr(analyze_mod, "_USE_CELERY", None, raising=False)
        cd.set_state(use_celery=False)

        result = analyze_mod._ensure_celery_initialized()
        assert result is False
        assert analyze_mod._USE_CELERY is False
