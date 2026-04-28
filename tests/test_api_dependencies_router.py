"""의존성 스캔 라우터 테스트 (tests/test_api_dependencies_router.py).

Wave 2-E: GET /api/dependencies, POST /api/dependencies/scan 의 동작과
응답 셰이프를 보존하기 위한 스모크 테스트. 외부 도구(pip-audit/npm)는
DependencyScanner 를 monkeypatch 하여 호출되지 않도록 한다.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api import result_sources
from api.routers import dependencies as deps_router
from api.server import app


_AUTH_HEADERS = {"X-API-Key": "test-api-key"}
client = TestClient(app)


# ============================================================
# 가짜 DependencyScanner / 결과
# ============================================================

class _FakeScanResult:
    """analyzer.dependency_scanner.DependencyScanResult 의 테스트 더블.

    실제 결과의 to_dict() 셰이프를 흉내낸다.
    """

    def __init__(self, tool: str, project_path: str = "", error: str | None = None):
        self.tool = tool
        self.project_path = project_path
        self.error = error

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "project_path": self.project_path,
            "summary": {
                "total_packages": 0,
                "total_vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "vulnerabilities": [],
            "packages": [],
            "error": self.error,
        }


class _FakeScanner:
    """외부 프로세스(pip-audit/npm) 를 절대 실행하지 않는 가짜 스캐너."""

    def __init__(self):
        self.calls = {
            "scan": [],
            "scan_requirements_text": [],
            "scan_package_json_text": [],
        }

    def scan(self, project_path: str):
        self.calls["scan"].append(project_path)
        return [_FakeScanResult(tool="pip-audit", project_path=project_path)]

    def scan_requirements_text(self, text: str):
        self.calls["scan_requirements_text"].append(text)
        return _FakeScanResult(tool="pip-audit", project_path="/tmp/fake-req")

    def scan_package_json_text(self, text: str):
        self.calls["scan_package_json_text"].append(text)
        return _FakeScanResult(tool="npm-audit", project_path="/tmp/fake-pkg")


@pytest.fixture
def fake_scanner(monkeypatch):
    """analyzer.dependency_scanner.DependencyScanner 를 가짜로 교체.

    라우터 핸들러는 함수 내부에서 lazy import 하므로,
    analyzer.dependency_scanner 모듈의 클래스 속성을 직접 패치한다.
    """
    import analyzer.dependency_scanner as ds_module

    instance = _FakeScanner()
    monkeypatch.setattr(ds_module, "DependencyScanner", lambda: instance)
    return instance


# ============================================================
# 인증 보호
# ============================================================

class TestDependenciesAuth:
    def test_get_requires_auth(self):
        r = client.get("/api/dependencies")
        assert r.status_code in (401, 403)

    def test_post_requires_auth(self):
        r = client.post(
            "/api/dependencies/scan",
            json={"requirements_text": "flask==2.0.0"},
        )
        assert r.status_code in (401, 403)


# ============================================================
# GET /api/dependencies
# ============================================================

class TestGetDependencies:
    REQUIRED_TOP = {"results"}
    REQUIRED_RESULT = {
        "tool", "project_path", "summary",
        "vulnerabilities", "packages", "error",
    }

    def test_response_shape(self, fake_scanner):
        r = client.get("/api/dependencies", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert set(data.keys()) == self.REQUIRED_TOP
        assert isinstance(data["results"], list)
        assert len(data["results"]) >= 1
        for item in data["results"]:
            assert self.REQUIRED_RESULT <= set(item.keys())

    def test_uses_shared_project_root(self, fake_scanner):
        """공유 헬퍼 result_sources.project_root() 가 스캐너에 전달돼야 한다."""
        r = client.get("/api/dependencies", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        assert fake_scanner.calls["scan"] == [result_sources.project_root()]


# ============================================================
# POST /api/dependencies/scan
# ============================================================

class TestPostDependenciesScan:
    REQUIRED_TOP = {"results"}

    def test_requirements_text_branch(self, fake_scanner):
        payload = {"requirements_text": "flask==2.0.0\nrequests==2.25.0"}
        r = client.post("/api/dependencies/scan", json=payload, headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert set(data.keys()) == self.REQUIRED_TOP
        assert len(data["results"]) == 1
        # requirements 분기만 호출되었는지
        assert fake_scanner.calls["scan_requirements_text"] == [payload["requirements_text"]]
        assert fake_scanner.calls["scan"] == []
        assert fake_scanner.calls["scan_package_json_text"] == []

    def test_package_json_text_branch(self, fake_scanner):
        payload = {"package_json_text": '{"dependencies": {"lodash": "4.17.0"}}'}
        r = client.post("/api/dependencies/scan", json=payload, headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert set(data.keys()) == self.REQUIRED_TOP
        assert len(data["results"]) == 1
        assert fake_scanner.calls["scan_package_json_text"] == [payload["package_json_text"]]
        assert fake_scanner.calls["scan"] == []
        assert fake_scanner.calls["scan_requirements_text"] == []

    def test_project_path_branch(self, fake_scanner, tmp_path):
        # 존재하는 경로만 사용해야 분기로 들어감 (라우터 내부 os.path.exists 검사)
        target = tmp_path / "proj"
        target.mkdir()
        payload = {"project_path": str(target)}
        r = client.post("/api/dependencies/scan", json=payload, headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert set(data.keys()) == self.REQUIRED_TOP
        assert fake_scanner.calls["scan"] == [str(target)]

    def test_default_to_project_root(self, fake_scanner):
        """모든 입력이 비어 있으면 현재 프로젝트(project_root) 를 스캔."""
        r = client.post("/api/dependencies/scan", json={}, headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert set(data.keys()) == self.REQUIRED_TOP
        assert fake_scanner.calls["scan"] == [result_sources.project_root()]

    def test_nonexistent_project_path_falls_through_to_root(self, fake_scanner):
        """존재하지 않는 project_path 는 무시되고 기본 분기로 떨어진다."""
        payload = {"project_path": "/__definitely_does_not_exist__/x"}
        r = client.post("/api/dependencies/scan", json=payload, headers=_AUTH_HEADERS)
        assert r.status_code == 200
        # 폴백 분기 → 현재 프로젝트 루트 스캔
        assert fake_scanner.calls["scan"] == [result_sources.project_root()]


# ============================================================
# 라우터/모듈 임포트 회귀 — api.server 미의존
# ============================================================

class TestRouterImportSurface:
    def test_module_does_not_import_api_server(self):
        """순환 import 회귀 방지 — 라우터는 api.server 를 import 하지 않아야 한다."""
        import ast
        import inspect

        import api.routers.dependencies as mod

        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name != "api.server", "api.server 직접 import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "api.server", "from api.server import 금지"

    def test_request_model_lives_in_router(self):
        """DependencyScanRequest 가 라우터 모듈에 위치하는지 확인."""
        assert hasattr(deps_router, "DependencyScanRequest")
