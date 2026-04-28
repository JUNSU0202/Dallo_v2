"""api/server.py sys.path 부트스트랩 회귀 테스트 (Wave 2-J).

api/server.py 는 본래 ``sys.path.insert(0, <project_root>)`` 라는 부트스트랩
해킹을 가지고 있었다. pytest.ini 의 ``pythonpath = .`` 도입과 Wave 2-H/2-I 의
부트스트랩 정리(설정/lifespan 분리) 로 인해 더 이상 필요하지 않다. 이 테스트는
다음을 보존한다:

  1) 소스 정적 검사: ``api/server.py`` 모듈 top-level 에 ``sys.path.insert``
     호출이 남아 있지 않다 (Wave 2-J 의 RED 가드).
  2) ``api.server`` 임포트가 sys.path 를 변경하지 않는다 (런타임 검증).
  3) ``uvicorn api.server:app`` 형태의 import string 이 sys.path 보강 없이도
     해석된다.
  4) Wave 2-H/2-I 의 lifespan/라우터 등록 동작이 유지된다.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import inspect
import json
import os
import subprocess
import sys
import textwrap

from fastapi import FastAPI
from fastapi.testclient import TestClient


_AUTH_HEADERS = {"X-API-Key": "test-api-key"}

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _source_has_sys_path_insert(source: str) -> bool:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # ``sys.path.insert(...)`` 형태 매칭
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "insert"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "path"
            and isinstance(func.value.value, ast.Name)
            and func.value.value.id == "sys"
        ):
            return True
    return False


class TestNoSysPathMutationInSource:
    """api/server.py 및 transitive 부트스트랩 모듈에 ``sys.path.insert`` 가 없어야 한다."""

    def test_api_server_source_has_no_syspath_insert_call(self):
        import api.server as server_mod

        assert not _source_has_sys_path_insert(inspect.getsource(server_mod)), (
            "api/server.py 모듈에 sys.path.insert 호출이 남아 있음 "
            "(Wave 2-J: 부트스트랩 해킹 제거 필요)"
        )

    def test_api_celery_app_source_has_no_syspath_insert_call(self):
        import api.celery_app as celery_mod

        assert not _source_has_sys_path_insert(inspect.getsource(celery_mod)), (
            "api/celery_app.py 모듈에 sys.path.insert 호출이 남아 있음 "
            "(Wave 2-J: 부트스트랩 해킹 제거 필요 — celery 는 cwd/pythonpath 로 해결)"
        )

    def test_api_tasks_source_has_no_syspath_insert_call(self):
        import api.tasks as tasks_mod

        assert not _source_has_sys_path_insert(inspect.getsource(tasks_mod)), (
            "api/tasks.py 모듈에 sys.path.insert 호출이 남아 있음 "
            "(Wave 2-J: 부트스트랩 해킹 제거 필요)"
        )

    def test_db_service_source_has_no_syspath_insert_call(self):
        import db.service as service_mod

        assert not _source_has_sys_path_insert(inspect.getsource(service_mod)), (
            "db/service.py 모듈에 sys.path.insert 호출이 남아 있음 "
            "(Wave 2-J: 부트스트랩 해킹 제거 필요)"
        )


class TestImportDoesNotMutateSysPath:
    """``api.server`` 임포트가 런타임에 sys.path 를 변경하지 않아야 한다."""

    def test_reimport_does_not_change_sys_path(self):
        # 이미 import 되어 있을 수 있으므로 한 번 비우고 재로딩한다.
        sys.modules.pop("api.server", None)

        before = list(sys.path)
        importlib.import_module("api.server")
        after = list(sys.path)

        assert before == after, (
            "api.server import 시 sys.path 가 변경되었음 — "
            f"diff: before={before!r}, after={after!r}"
        )


class TestFreshSubprocessImportDoesNotMutateSysPath:
    """fresh subprocess 에서 ``api.server`` 임포트가 sys.path 를 변경하지 않아야 한다.

    in-process ``import`` 검사는 conftest 가 미리 다른 경로를 잡아 두면 차이가
    상쇄돼 false-negative 가 난다 (직접 server.py 가 아니라 transitive import 에서
    sys.path.insert 를 호출하는 경우). 별도 파이썬 인터프리터를 띄워야만 진짜
    "임포트 시 sys.path 가 변하지 않는가" 를 검증할 수 있다.
    """

    def test_fresh_subprocess_import_keeps_sys_path_stable(self):
        script = textwrap.dedent(
            """
            import json
            import sys

            before = list(sys.path)
            import api.server  # noqa: F401
            after = list(sys.path)

            added = [p for p in after if p not in before]
            print(json.dumps({"added": added, "before_len": len(before), "after_len": len(after)}))
            """
        )

        env = os.environ.copy()
        # 테스트용 안전 기본값 — conftest 가 in-process 로만 적용되므로
        # subprocess 에는 명시적으로 다시 주입한다.
        env.setdefault("DALLO_ENCRYPTION_KEY", "test-key")
        env.setdefault("DALLO_API_KEYS", "test-api-key")
        # PYTHONPATH 로 보조 경로를 미리 깔지 않는다 — 그러면 검증 의미가 사라진다.
        env.pop("PYTHONPATH", None)

        proc = subprocess.run(
            [sys.executable, "-c", script],
            cwd=_PROJECT_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert proc.returncode == 0, (
            f"fresh subprocess import 실패\nstdout={proc.stdout!r}\nstderr={proc.stderr!r}"
        )

        payload = json.loads(proc.stdout.strip().splitlines()[-1])
        assert payload["added"] == [], (
            "fresh subprocess 에서 api.server 임포트가 sys.path 를 변경했다 — "
            f"added={payload['added']!r} (transitive 모듈의 sys.path.insert 잔존)"
        )


class TestUvicornImportString:
    """``uvicorn api.server:app`` 형태의 import string 이 해석 가능해야 한다.

    uvicorn 은 import string 을 ``importlib.import_module`` 로 해석하므로,
    server.py 의 sys.path 보강 없이도 표준 패키지 검색으로 모듈이 잡혀야 한다.
    """

    def test_module_resolvable_via_importlib(self):
        spec = importlib.util.find_spec("api.server")
        assert spec is not None and spec.origin is not None

    def test_app_attribute_is_fastapi_instance(self):
        mod = importlib.import_module("api.server")
        app = getattr(mod, "app", None)
        assert isinstance(app, FastAPI)


class TestLifespanStillIntact:
    """Wave 2-I 의 lifespan 동작이 여전히 정상이어야 한다."""

    def test_root_endpoint_via_context_manager(self):
        from api.server import app

        with TestClient(app) as client:
            r = client.get("/")
            assert r.status_code == 200
            assert r.json()["message"] == "Dallo DevSecOps API"

    def test_protected_endpoint_via_context_manager(self):
        from api.server import app

        with TestClient(app) as client:
            r = client.get("/api/stats", headers=_AUTH_HEADERS)
            assert r.status_code == 200
            data = r.json()
            assert "total_issues" in data


class TestRoutesStillRegistered:
    """라우터 include 회귀 가드 — 라우트 셋이 보존되어야 한다."""

    def test_root_dashboard_and_api_routes_present(self):
        from api.server import app

        paths = {getattr(r, "path", None) for r in app.routes}
        assert "/" in paths
        assert "/dashboard" in paths
        api_paths = [p for p in paths if isinstance(p, str) and p.startswith("/api/")]
        assert len(api_paths) > 0
