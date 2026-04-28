"""api/server.py lifespan 부트스트랩 회귀 테스트 (Wave 2-I).

api/server.py 가 모듈 임포트 시점에 ``init_db()`` 를 호출하던 부수효과를
FastAPI lifespan(애플리케이션 시작 훅) 으로 옮겼다. 이 테스트는 그 동작을
보존한다:

  1) ``api.server`` 임포트가 성공하고 ``app`` 객체가 노출된다.
  2) ``with TestClient(app) as client:`` 형태로 사용하면 lifespan 이 발화하여
     ``init_db`` 가 호출되고 루트(`/`) 엔드포인트가 정상 동작한다.
  3) lifespan 시작 시 ``init_db`` 가 호출되며, TestClient 컨텍스트 매니저
     수명 1회당 정확히 1회만 호출된다 (매 요청마다 init 이 도는 회귀 차단).
  4) 주요 라우트(루트 + /api/* 라우터들) 가 그대로 등록되어 있다.

설계 메모:
  - ``api.server`` 는 ``from db.models import init_db`` 로 이름을 바인딩해
    두기 때문에, 테스트에서 ``api.server.init_db`` 를 monkeypatch 하면
    lifespan 본체가 참조하는 호출이 패치본으로 바뀐다.
  - conftest.py 가 세션 시작 시 한 번 ``init_db()`` 를 호출하지만, 그 호출은
    monkeypatch 가 적용되기 전이므로 본 테스트의 spy 카운트와 무관하다.
"""

from __future__ import annotations

import ast
import inspect

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


_AUTH_HEADERS = {"X-API-Key": "test-api-key"}


class TestImportSurface:
    """모듈 임포트 자체가 안전하고 ``app`` 이 노출되어야 한다."""

    def test_import_exposes_app(self):
        from api.server import app

        assert isinstance(app, FastAPI)
        assert app.title == "Dallo DevSecOps API"
        assert app.version == "1.0.0"

    def test_import_does_not_call_init_db_at_module_top_level(self):
        """소스 정적 검사: 모듈 top-level 에 ``init_db()`` 호출이 남아 있지 않아야 한다.

        Wave 2-I 의 핵심 변경 — 부트스트랩 부수효과를 lifespan 으로 이동.
        리뷰어가 실수로 모듈 top-level 에 ``init_db()`` 를 다시 추가하지
        않도록 정적으로 가드한다. lifespan 함수 내부 호출은 함수 본체이므로
        top-level 검사에 걸리지 않는다.
        """
        import api.server as server_mod

        src = inspect.getsource(server_mod)
        tree = ast.parse(src)
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                func = node.value.func
                # ``init_db()`` 직접 호출 차단
                if isinstance(func, ast.Name) and func.id == "init_db":
                    pytest.fail("모듈 top-level 에 init_db() 호출이 남아 있음")
                # ``something.init_db()`` 호출 차단
                if isinstance(func, ast.Attribute) and func.attr == "init_db":
                    pytest.fail("모듈 top-level 에 *.init_db() 호출이 남아 있음")


class TestLifespanRunsStartup:
    """TestClient 컨텍스트 매니저 사용 시 lifespan 이 정상 발화한다."""

    def test_root_endpoint_via_context_manager(self):
        from api.server import app

        with TestClient(app) as client:
            r = client.get("/")
            assert r.status_code == 200
            assert r.json()["message"] == "Dallo DevSecOps API"

    def test_protected_endpoint_via_context_manager(self):
        """startup 후 인증 헤더로 보호 엔드포인트도 정상 동작."""
        from api.server import app

        with TestClient(app) as client:
            r = client.get("/api/stats", headers=_AUTH_HEADERS)
            assert r.status_code == 200
            data = r.json()
            assert "total_issues" in data


class TestInitDbCalledByLifespan:
    """lifespan 시작 시 ``init_db`` 가 호출되며 TestClient 수명 1회당 정확히 1회."""

    def test_init_db_called_during_startup(self, monkeypatch):
        import api.server as server_mod

        calls: list[int] = []

        def _spy() -> None:
            calls.append(1)

        # api.server 모듈이 ``from db.models import init_db`` 로 바인딩한
        # 이름을 패치 — lifespan 본체에서의 호출이 spy 로 라우팅된다.
        monkeypatch.setattr(server_mod, "init_db", _spy)

        with TestClient(server_mod.app) as client:
            # 첫 요청 시점에는 이미 lifespan startup 이 끝나 있어야 한다
            r = client.get("/")
            assert r.status_code == 200

        # 컨텍스트 매니저 1회 = startup 1회 = init_db 호출 1회
        assert calls == [1], f"init_db 가 정확히 1번 호출되어야 함, 실제={len(calls)}"

    def test_init_db_not_called_per_request(self, monkeypatch):
        """매 요청마다 init_db 가 다시 도는 회귀를 차단."""
        import api.server as server_mod

        calls: list[int] = []
        monkeypatch.setattr(server_mod, "init_db", lambda: calls.append(1))

        with TestClient(server_mod.app) as client:
            client.get("/")
            client.get("/")
            client.get("/api/stats", headers=_AUTH_HEADERS)

        # 요청 3회 했지만 init_db 는 startup 시 1회만 호출되어야 한다
        assert len(calls) == 1


class TestRoutesRegistered:
    """라우트 등록 회귀 가드 — 라우터 분리 작업의 누적 검증."""

    def test_root_and_api_routes_registered(self):
        from api.server import app

        paths = {getattr(r, "path", None) for r in app.routes}
        # 루트 + 대시보드 SPA + 주요 API 엔드포인트가 등록되어 있어야 함
        assert "/" in paths
        assert "/dashboard" in paths
        # /api/* 라우터들이 최소 한 개 이상 include 되어 있어야 함
        api_paths = [p for p in paths if isinstance(p, str) and p.startswith("/api/")]
        assert len(api_paths) > 0, "api/* 엔드포인트가 하나도 등록되지 않음"
