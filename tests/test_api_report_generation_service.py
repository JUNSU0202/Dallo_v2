"""리포트 생성 서비스 모듈 단위 테스트 (tests/test_api_report_generation_service.py).

Wave 2-R: ``api/routers/report.py`` 에서 데이터 로드/의존성 스캔 헬퍼
로직을 분리한 ``api.services.report_generation`` 서비스의 단위 테스트.

검증 대상:
  - 서비스 모듈은 FastAPI / api.server 를 import 하지 않는다.
  - ``load_report_data(session_id)`` 가 DB → JSON 폴백 순서로 동작한다.
  - DB 가 비어 있고 ``load_full_result`` 도 빈 dict 면 ``None`` 을 반환한다.
  - ``scan_dependencies_safely`` 가 ``DependencyScanner`` 를 lazy import 하여
    ``project_root()`` 경로로 스캔하고, 결과 dict 셰이프를 보존한다.
  - 스캐너 실패는 None 으로 흡수된다 (리포트 생성 자체는 막지 않는다).
  - 리포트 라우터는 서비스 함수에 위임하여 generate/preview 응답을 만든다.
"""

from __future__ import annotations

import ast
import inspect

import pytest
from fastapi.testclient import TestClient

from api import result_sources
from api.server import app
from db import service as db_service


_AUTH_HEADERS = {"X-API-Key": "test-api-key"}
client = TestClient(app)


# ============================================================
# Import surface
# ============================================================

class TestServiceImportSurface:
    def _module_source(self) -> str:
        from api.services import report_generation as svc

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
                    "fastapi import 금지"
                )

    def test_service_does_not_import_dependency_scanner_at_top_level(self):
        """``DependencyScanner`` 는 호출 시점에만 lazy import 되어야 한다."""
        tree = ast.parse(self._module_source())
        for node in tree.body:  # 모듈 최상위 import 만 검사
            if isinstance(node, ast.ImportFrom):
                assert node.module != "analyzer.dependency_scanner", (
                    "최상위에서 analyzer.dependency_scanner import 금지"
                )


# ============================================================
# load_report_data — DB / JSON fallback
# ============================================================

class TestLoadReportData:
    def test_session_id_routes_to_get_analysis_by_session(self, monkeypatch):
        from api.services import report_generation as svc

        called = {"by_session": 0, "latest": 0}
        payload = {"session_id": "abc123", "summary": {"total": 0}}

        def by_session(sid):
            called["by_session"] += 1
            assert sid == "abc123"
            return payload

        def latest():
            called["latest"] += 1
            return None

        monkeypatch.setattr(db_service, "get_analysis_by_session", by_session)
        monkeypatch.setattr(db_service, "get_latest_analysis", latest)

        result = svc.load_report_data("abc123")
        assert result is payload
        assert called == {"by_session": 1, "latest": 0}

    def test_no_session_id_routes_to_get_latest_analysis(self, monkeypatch):
        from api.services import report_generation as svc

        called = {"by_session": 0, "latest": 0}
        payload = {"session_id": "latest_x", "summary": {"total": 0}}

        def by_session(sid):
            called["by_session"] += 1
            return None

        def latest():
            called["latest"] += 1
            return payload

        monkeypatch.setattr(db_service, "get_analysis_by_session", by_session)
        monkeypatch.setattr(db_service, "get_latest_analysis", latest)

        result = svc.load_report_data(None)
        assert result is payload
        assert called == {"by_session": 0, "latest": 1}

    def test_db_empty_falls_back_to_load_full_result(self, monkeypatch):
        from api.services import report_generation as svc

        fallback_payload = {"session_id": "fallback", "summary": {"total": 0}}

        monkeypatch.setattr(db_service, "get_latest_analysis", lambda: None)
        monkeypatch.setattr(
            result_sources, "load_full_result", lambda: fallback_payload,
        )

        result = svc.load_report_data(None)
        assert result == fallback_payload

    def test_db_empty_and_full_result_empty_returns_none(self, monkeypatch):
        from api.services import report_generation as svc

        monkeypatch.setattr(db_service, "get_latest_analysis", lambda: None)
        monkeypatch.setattr(result_sources, "load_full_result", lambda: {})

        assert svc.load_report_data(None) is None

    def test_db_empty_and_full_result_empty_returns_none_with_session_id(
        self, monkeypatch,
    ):
        from api.services import report_generation as svc

        monkeypatch.setattr(db_service, "get_analysis_by_session", lambda sid: None)
        monkeypatch.setattr(result_sources, "load_full_result", lambda: {})

        assert svc.load_report_data("missing_session") is None


# ============================================================
# scan_dependencies_safely — fake scanner
# ============================================================

class _FakeScanResult:
    def __init__(self, project_path: str):
        self.project_path = project_path

    def to_dict(self) -> dict:
        return {
            "tool": "fake",
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
            "error": None,
        }


class _FakeScanner:
    def __init__(self):
        self.calls: list[str] = []

    def scan(self, project_path: str):
        self.calls.append(project_path)
        return [_FakeScanResult(project_path)]


class _RaisingScanner:
    def scan(self, project_path: str):
        raise RuntimeError("boom")


class TestScanDependenciesSafely:
    def test_uses_project_root_and_returns_results_dict(self, monkeypatch):
        from api.services import report_generation as svc
        import analyzer.dependency_scanner as ds_module

        instance = _FakeScanner()
        monkeypatch.setattr(ds_module, "DependencyScanner", lambda: instance)

        result = svc.scan_dependencies_safely()

        assert isinstance(result, dict)
        assert "results" in result
        assert isinstance(result["results"], list)
        assert len(result["results"]) == 1
        assert instance.calls == [result_sources.project_root()]
        assert result["results"][0]["tool"] == "fake"
        assert result["results"][0]["project_path"] == result_sources.project_root()

    def test_returns_none_when_scanner_raises(self, monkeypatch):
        from api.services import report_generation as svc
        import analyzer.dependency_scanner as ds_module

        monkeypatch.setattr(ds_module, "DependencyScanner", lambda: _RaisingScanner())

        assert svc.scan_dependencies_safely() is None

    def test_returns_none_when_scanner_constructor_raises(self, monkeypatch):
        from api.services import report_generation as svc
        import analyzer.dependency_scanner as ds_module

        def boom():
            raise RuntimeError("cannot init")

        monkeypatch.setattr(ds_module, "DependencyScanner", boom)

        assert svc.scan_dependencies_safely() is None


# ============================================================
# 라우터 위임 — generate/preview 가 서비스 함수를 호출한다
# ============================================================

class _StubGenerator:
    """save_report / generate_html / generate_markdown 만 fake 로 답한다."""

    def save_report(self, data, output_dir, fmt="html", include_deps=None):
        import os

        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "stub.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write("<html>stub</html>")
        return {"html": path}

    def generate_html(self, data, deps_data=None):
        return "<html>stub</html>"

    def generate_markdown(self, data, deps_data=None):
        return "# stub"


@pytest.fixture
def stub_report_generator(monkeypatch):
    import sys
    import types

    fake_module = types.ModuleType("reports.report_generator")
    fake_module.ReportGenerator = _StubGenerator
    fake_pkg = types.ModuleType("reports")
    fake_pkg.report_generator = fake_module

    monkeypatch.setitem(sys.modules, "reports", fake_pkg)
    monkeypatch.setitem(sys.modules, "reports.report_generator", fake_module)
    return fake_module


@pytest.fixture
def temp_reports_dir(tmp_path, monkeypatch):
    target = tmp_path / "reports"
    target.mkdir()
    monkeypatch.setattr(result_sources, "REPORTS_DIR", str(target))
    return str(target)


class TestRouterDelegatesToService:
    """라우터는 서비스 함수에 위임해야 한다.

    db_service / result_sources.load_full_result 직접 호출 패턴을 monkeypatch
    하면 라우터가 그것을 그대로 부르는 한 통과하지만, 본 테스트는 *서비스*
    함수만 monkeypatch 하여 라우터가 서비스 경유로 데이터를 받아오는지를
    확인한다.
    """

    def test_generate_uses_service_load_report_data(
        self, monkeypatch, stub_report_generator, temp_reports_dir,
    ):
        from api.services import report_generation as svc

        captured: dict = {"sid": object()}
        synthetic = {"session_id": "via-service", "summary": {"total": 0}}

        def fake_load(session_id):
            captured["sid"] = session_id
            return synthetic

        # DB / JSON 둘 다 None 으로 만들어, 서비스 경유가 아니라면 error 가
        # 떨어지도록 한다.
        monkeypatch.setattr(db_service, "get_latest_analysis", lambda: None)
        monkeypatch.setattr(db_service, "get_analysis_by_session", lambda sid: None)
        monkeypatch.setattr(result_sources, "load_full_result", lambda: {})
        monkeypatch.setattr(svc, "load_report_data", fake_load)

        r = client.get("/api/report/generate?fmt=html", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "generated"
        assert captured["sid"] is None

    def test_generate_passes_session_id_through_service(
        self, monkeypatch, stub_report_generator, temp_reports_dir,
    ):
        from api.services import report_generation as svc

        seen = {"sid": None}
        synthetic = {"session_id": "abc", "summary": {"total": 0}}

        def fake_load(session_id):
            seen["sid"] = session_id
            return synthetic

        monkeypatch.setattr(db_service, "get_latest_analysis", lambda: None)
        monkeypatch.setattr(db_service, "get_analysis_by_session", lambda sid: None)
        monkeypatch.setattr(result_sources, "load_full_result", lambda: {})
        monkeypatch.setattr(svc, "load_report_data", fake_load)

        r = client.get(
            "/api/report/generate?fmt=html&session_id=abc",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 200, r.text
        assert seen["sid"] == "abc"

    def test_generate_uses_service_scan_dependencies_when_include_deps(
        self, monkeypatch, stub_report_generator, temp_reports_dir,
    ):
        from api.services import report_generation as svc

        synthetic = {"session_id": "d", "summary": {"total": 0}}
        scanned: dict = {"called": 0}

        def fake_scan():
            scanned["called"] += 1
            return {"results": [{"tool": "fake-from-service"}]}

        monkeypatch.setattr(svc, "load_report_data", lambda sid: synthetic)
        monkeypatch.setattr(svc, "scan_dependencies_safely", fake_scan)

        r = client.get(
            "/api/report/generate?fmt=html&include_deps=true",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 200, r.text
        assert scanned["called"] == 1

    def test_generate_does_not_scan_when_include_deps_false(
        self, monkeypatch, stub_report_generator, temp_reports_dir,
    ):
        from api.services import report_generation as svc

        synthetic = {"session_id": "d", "summary": {"total": 0}}
        scanned: dict = {"called": 0}

        def fake_scan():
            scanned["called"] += 1
            return {"results": []}

        monkeypatch.setattr(svc, "load_report_data", lambda sid: synthetic)
        monkeypatch.setattr(svc, "scan_dependencies_safely", fake_scan)

        r = client.get(
            "/api/report/generate?fmt=html",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 200
        assert scanned["called"] == 0

    def test_preview_uses_service_load_report_data(
        self, monkeypatch, stub_report_generator,
    ):
        from api.services import report_generation as svc

        seen = {"sid": object()}

        def fake_load(session_id):
            seen["sid"] = session_id
            return None

        # 서비스가 None 을 돌려주면 라우터는 error payload 를 반환해야 한다.
        # 직접 의존을 우회하는지 확인하기 위해 db_service / load_full_result 는
        # 정상 데이터를 돌려줘도 라우터가 그것을 그대로 쓰지 않아야 한다.
        monkeypatch.setattr(
            db_service, "get_latest_analysis",
            lambda: {"session_id": "not-via-service", "summary": {"total": 0}},
        )
        monkeypatch.setattr(svc, "load_report_data", fake_load)

        r = client.get("/api/report/preview", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        assert r.json() == {"error": "분석 데이터가 없습니다."}
        assert seen["sid"] is None

    def test_preview_uses_service_scan_dependencies(
        self, monkeypatch, stub_report_generator,
    ):
        from api.services import report_generation as svc

        synthetic = {"session_id": "d", "summary": {"total": 0}}
        scanned: dict = {"called": 0}

        def fake_scan():
            scanned["called"] += 1
            return {"results": [{"tool": "fake-from-service"}]}

        monkeypatch.setattr(svc, "load_report_data", lambda sid: synthetic)
        monkeypatch.setattr(svc, "scan_dependencies_safely", fake_scan)

        r = client.get(
            "/api/report/preview?include_deps=true",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 200, r.text
        assert scanned["called"] == 1


__all__: list[str] = []
