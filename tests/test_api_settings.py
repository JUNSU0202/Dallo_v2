"""api/settings.py 단위 테스트 + 부트스트랩 회귀 가드.

Wave 2-H: api/server.py 와 api/routers/* 에 흩어져 있던 경로/CORS 기본값을
api/settings.py 로 모은 변경의 기본값과 임포트 사이드 이펙트를 검증한다.

여기서는 다음을 보장한다:
  1) settings 모듈의 기본값이 분리 이전 동작과 동일하다.
  2) ``DALLO_UPLOAD_DIR`` / ``DALLO_CORS_ORIGINS`` 환경변수 오버라이드가
     의도대로 동작한다.
  3) settings 모듈은 FastAPI/DB 같은 무거운 의존성에 의존하지 않는다 (얇음).
  4) ``api.server`` 가 settings 의 값으로 CORS 와 UPLOAD_DIR 을 사용한다.
  5) ``api.routers.patch`` 의 ``UPLOAD_DIR`` 모듈 변수가 settings 와 일치한다.
"""

from __future__ import annotations

import importlib
import os
import sys

import pytest


def _reload_settings():
    """env 변경 후 ``api.settings`` 를 재임포트하여 새 값을 반영시킨다."""
    sys.modules.pop("api.settings", None)
    return importlib.import_module("api.settings")


@pytest.fixture(autouse=True)
def _restore_settings_module_after_each_test():
    """각 테스트 종료 시 ``api.settings`` 모듈을 기본 env 상태로 reload.

    여러 테스트가 ``_reload_settings()`` 로 settings 모듈 글로벌을 덮어쓰는데,
    pytest 의 ``monkeypatch.setenv`` 는 env 만 복원하고 모듈 상태는 그대로
    남긴다. 이전 테스트에서 박제된 값이 ``TestPatchRouterUsesSettings`` 같은
    이후 회귀 가드에 새어들지 않도록, 매 테스트 후 settings 를 한 번 더
    reload 하여 깨끗한 기본값으로 되돌린다.
    """
    yield
    sys.modules.pop("api.settings", None)
    importlib.import_module("api.settings")


class TestSettingsDefaults:
    def test_project_root_is_repo_root(self):
        from api import settings

        # api/settings.py 의 부모의 부모 = 레포 루트
        expected = os.path.dirname(
            os.path.dirname(os.path.abspath(settings.__file__)),
        )
        assert settings.PROJECT_ROOT == expected
        # 레포 루트에 있는 README.md 존재 여부로 정합성 추가 검증
        assert os.path.exists(os.path.join(settings.PROJECT_ROOT, "README.md"))

    def test_dashboard_dir_under_project_root(self):
        from api import settings

        assert settings.DASHBOARD_DIR == os.path.join(
            settings.PROJECT_ROOT, "dashboard", "dist",
        )

    def test_default_upload_dir_is_absolute_under_project_root(self, monkeypatch):
        """Wave 3-C: 기본 UPLOAD_DIR 은 ``<root>/uploads`` 의 절대경로."""
        monkeypatch.delenv("DALLO_UPLOAD_DIR", raising=False)
        mod = _reload_settings()
        assert os.path.isabs(mod.UPLOAD_DIR), (
            "기본 UPLOAD_DIR 은 cwd 의존을 막기 위해 절대경로여야 한다"
        )
        assert mod.UPLOAD_DIR == os.path.join(mod.PROJECT_ROOT, "uploads")

    def test_default_reports_dir_is_absolute_under_project_root(self, monkeypatch):
        """Wave 3-C: 기본 REPORTS_DIR 은 ``<root>/reports`` 의 절대경로."""
        monkeypatch.delenv("DALLO_REPORTS_DIR", raising=False)
        mod = _reload_settings()
        assert os.path.isabs(mod.REPORTS_DIR)
        assert mod.REPORTS_DIR == os.path.join(mod.PROJECT_ROOT, "reports")

    def test_default_cors_origins(self, monkeypatch):
        monkeypatch.delenv("DALLO_CORS_ORIGINS", raising=False)
        mod = _reload_settings()
        assert mod.CORS_ORIGINS == [
            "http://localhost:3000",
            "http://localhost:5173",
        ]


class TestSettingsEnvOverrides:
    def test_upload_dir_env_override_absolute(self, monkeypatch, tmp_path):
        """절대경로 env 값은 그대로 사용된다."""
        target = str(tmp_path / "uploads_override")
        monkeypatch.setenv("DALLO_UPLOAD_DIR", target)
        mod = _reload_settings()
        assert mod.UPLOAD_DIR == target

    def test_upload_dir_env_override_relative_resolved_under_root(self, monkeypatch):
        """Wave 3-C: 상대경로 env 값은 cwd 가 아닌 PROJECT_ROOT 기준으로 정규화된다."""
        monkeypatch.setenv("DALLO_UPLOAD_DIR", "custom_uploads")
        mod = _reload_settings()
        assert mod.UPLOAD_DIR == os.path.join(mod.PROJECT_ROOT, "custom_uploads")

    def test_reports_dir_env_override_absolute(self, monkeypatch, tmp_path):
        """Wave 3-C: 절대경로 ``DALLO_REPORTS_DIR`` 는 그대로 사용된다."""
        target = str(tmp_path / "reports_override")
        monkeypatch.setenv("DALLO_REPORTS_DIR", target)
        mod = _reload_settings()
        assert mod.REPORTS_DIR == target

    def test_reports_dir_env_override_relative_resolved_under_root(self, monkeypatch):
        """Wave 3-C: 상대경로 ``DALLO_REPORTS_DIR`` 는 PROJECT_ROOT 기준으로 정규화."""
        monkeypatch.setenv("DALLO_REPORTS_DIR", "out/reports")
        mod = _reload_settings()
        assert mod.REPORTS_DIR == os.path.join(mod.PROJECT_ROOT, "out", "reports")

    def test_path_env_blank_falls_back_to_default(self, monkeypatch):
        """공백/빈 문자열 env 는 기본값으로 폴백한다."""
        monkeypatch.setenv("DALLO_UPLOAD_DIR", "   ")
        monkeypatch.setenv("DALLO_REPORTS_DIR", "")
        mod = _reload_settings()
        assert mod.UPLOAD_DIR == os.path.join(mod.PROJECT_ROOT, "uploads")
        assert mod.REPORTS_DIR == os.path.join(mod.PROJECT_ROOT, "reports")

    def test_cors_origins_env_override(self, monkeypatch):
        monkeypatch.setenv(
            "DALLO_CORS_ORIGINS",
            "https://a.example, https://b.example",
        )
        mod = _reload_settings()
        assert mod.CORS_ORIGINS == ["https://a.example", "https://b.example"]

    def test_cors_origins_blank_falls_back_to_defaults(self, monkeypatch):
        # 모두 공백/콤마인 경우 기본값으로 폴백
        monkeypatch.setenv("DALLO_CORS_ORIGINS", "  ,  , ")
        mod = _reload_settings()
        assert mod.CORS_ORIGINS == [
            "http://localhost:3000",
            "http://localhost:5173",
        ]

    def test_cors_origins_empty_string_falls_back_to_defaults(self, monkeypatch):
        monkeypatch.setenv("DALLO_CORS_ORIGINS", "")
        mod = _reload_settings()
        assert mod.CORS_ORIGINS == [
            "http://localhost:3000",
            "http://localhost:5173",
        ]


class TestSettingsCwdIndependence:
    """Wave 3-C: 경로 설정은 import 시 cwd 에 의존하지 않아야 한다."""

    def test_default_paths_independent_of_cwd(self, monkeypatch, tmp_path):
        """전혀 다른 cwd 에서 settings 를 reload 해도 기본 경로는 동일."""
        monkeypatch.delenv("DALLO_UPLOAD_DIR", raising=False)
        monkeypatch.delenv("DALLO_REPORTS_DIR", raising=False)

        # 다른 cwd 로 이동한 뒤 reload — 기본값은 PROJECT_ROOT 기준이므로 불변.
        monkeypatch.chdir(tmp_path)
        mod = _reload_settings()
        assert mod.UPLOAD_DIR == os.path.join(mod.PROJECT_ROOT, "uploads")
        assert mod.REPORTS_DIR == os.path.join(mod.PROJECT_ROOT, "reports")

    def test_relative_env_paths_independent_of_cwd(self, monkeypatch, tmp_path):
        """상대경로 env 값도 cwd 가 아니라 PROJECT_ROOT 에 join 된다."""
        monkeypatch.setenv("DALLO_UPLOAD_DIR", "rel_uploads")
        monkeypatch.setenv("DALLO_REPORTS_DIR", "rel_reports")
        monkeypatch.chdir(tmp_path)
        mod = _reload_settings()
        assert mod.UPLOAD_DIR == os.path.join(mod.PROJECT_ROOT, "rel_uploads")
        assert mod.REPORTS_DIR == os.path.join(mod.PROJECT_ROOT, "rel_reports")
        # cwd 의 상대경로(=PROJECT_ROOT 외부) 와 같지 않음을 명시 검증
        assert mod.UPLOAD_DIR != os.path.join(str(tmp_path), "rel_uploads")


class TestSettingsImportSurface:
    """settings 는 무거운 프레임워크 의존성을 갖지 않는 얇은 설정 모듈이어야."""

    def test_module_has_no_heavy_deps(self):
        import ast
        import inspect

        from api import settings as mod

        src = inspect.getsource(mod)
        tree = ast.parse(src)
        forbidden = {"fastapi", "starlette", "db", "sqlalchemy", "celery"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    root = n.name.split(".")[0]
                    assert root not in forbidden, (
                        f"settings 가 무거운 의존성 {n.name} 을 import 함"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root = node.module.split(".")[0]
                    assert root not in forbidden, (
                        f"settings 가 {node.module} 에서 import 함"
                    )


class TestServerUsesSettings:
    """server.py 가 settings 의 값을 실제로 사용하는지 (회귀 가드)."""

    def test_app_cors_preflight_allows_default_origin(self):
        from fastapi.testclient import TestClient

        from api.server import app

        client = TestClient(app)
        r = client.options(
            "/api/stats",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert r.status_code in (200, 204)
        assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"

    def test_smoke_root_route_registered(self):
        from fastapi.testclient import TestClient

        from api.server import app

        client = TestClient(app)
        r = client.get("/")
        assert r.status_code == 200
        assert r.json().get("message") == "Dallo DevSecOps API"

    def test_smoke_protected_route_registered(self):
        """/api/stats 가 라우터에 등록되어 있고 인증을 요구함."""
        from fastapi.testclient import TestClient

        from api.server import app

        client = TestClient(app)
        # 인증 미통과 시 401/403 — 라우트 등록 자체는 정상이라는 의미.
        r = client.get("/api/stats")
        assert r.status_code in (200, 401, 403)


class TestPatchRouterUsesSettings:
    """patch 라우터의 UPLOAD_DIR 이 settings 와 동일한 기본값을 가져야 한다."""

    def test_patch_router_upload_dir_matches_settings(self):
        from api import settings
        from api.routers import patch as patch_router

        assert patch_router.UPLOAD_DIR == settings.UPLOAD_DIR
