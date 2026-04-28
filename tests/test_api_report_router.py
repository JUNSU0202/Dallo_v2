"""리포트 라우터 테스트 (tests/test_api_report_router.py).

Wave 2-D: GET /api/report/{generate,download/{filename},preview} 의
동작과 셰이프를 보존하기 위한 스모크 테스트. 외부 네트워크/실제 LLM 호출
없이 ReportGenerator 와 result_sources 를 monkeypatch 하여 검증한다.

또한 서비스 부트스트랩 스모크(GET /) 를 함께 확인한다.
"""

from __future__ import annotations

import os
import sys
import types

import pytest
from fastapi.testclient import TestClient

from api import result_sources
from api.server import app
from db import service as db_service


_AUTH_HEADERS = {"X-API-Key": "test-api-key"}
client = TestClient(app)


# ============================================================
# 가짜 ReportGenerator
# ============================================================

class _FakeReportGenerator:
    """reports.report_generator.ReportGenerator 의 테스트 더블.

    실제 모듈은 운영 환경/별도 패키지에 존재하므로 테스트에서는
    sys.modules 에 가짜 모듈을 주입하여 라우터의 lazy import 를 가로챈다.
    """

    def save_report(self, data, output_dir, fmt="html", include_deps=None):
        os.makedirs(output_dir, exist_ok=True)
        files: dict[str, str] = {}
        if fmt in ("html", "both"):
            html_path = os.path.join(output_dir, "report.html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write("<html><body>fake</body></html>")
            files["html"] = html_path
        if fmt in ("md", "both"):
            md_path = os.path.join(output_dir, "report.md")
            with open(md_path, "w", encoding="utf-8") as f:
                f.write("# fake report")
            files["md"] = md_path
        return files

    def generate_html(self, data, deps_data=None):
        return "<html><body>fake-preview</body></html>"

    def generate_markdown(self, data, deps_data=None):
        return "# fake-preview"


@pytest.fixture
def fake_report_generator(monkeypatch):
    """sys.modules 에 fake reports.report_generator 모듈을 주입."""
    fake_module = types.ModuleType("reports.report_generator")
    fake_module.ReportGenerator = _FakeReportGenerator
    fake_pkg = types.ModuleType("reports")
    fake_pkg.report_generator = fake_module

    monkeypatch.setitem(sys.modules, "reports", fake_pkg)
    monkeypatch.setitem(sys.modules, "reports.report_generator", fake_module)
    return fake_module


@pytest.fixture
def temp_reports_dir(tmp_path, monkeypatch):
    """REPORTS_DIR 을 tmp_path 로 격리."""
    target = tmp_path / "reports"
    target.mkdir()
    monkeypatch.setattr(result_sources, "REPORTS_DIR", str(target))
    return str(target)


@pytest.fixture
def synthetic_data():
    return {
        "session_id": "report_router_test_session",
        "summary": {"total": 1, "high": 1, "medium": 0, "low": 0,
                    "patches_generated": 0, "patches_verified": 0},
        "vulnerabilities": [],
        "patches": [],
    }


# ============================================================
# 부트스트랩 스모크 — GET /
# ============================================================

class TestServiceBootstrap:
    def test_root_smoke(self):
        """app 임포트 + GET / 200 — 라우터 분리 후 부트스트랩 실패 회귀 차단."""
        r = client.get("/")
        assert r.status_code == 200
        assert r.json()["message"] == "Dallo DevSecOps API"


# ============================================================
# 회귀 스모크 — reports.report_generator 실모듈 임포트 보증
# ============================================================
# Wave 2-D 리팩터 직후 reports/report_generator.py 가 누락되어
# /api/report/preview 호출 시 ModuleNotFoundError 가 발생했던 사고를
# 차단하기 위한 테스트. fake_report_generator fixture 를 의도적으로
# 사용하지 않아, 실제 reports.report_generator 가 import 가능한지를 검증한다.

class TestReportGeneratorImportSmoke:
    """reports.report_generator 실모듈이 항상 import 가능해야 한다."""

    def test_module_is_importable(self):
        """라우터의 lazy import 와 동일한 경로로 모듈을 직접 import."""
        from reports.report_generator import ReportGenerator  # noqa: F401

    def test_preview_no_data_does_not_raise_module_not_found(self, monkeypatch):
        """데이터가 비어 있어도 응답은 정상 error payload — 임포트 실패 회귀 차단."""
        monkeypatch.setattr(db_service, "get_latest_analysis", lambda: None)
        monkeypatch.setattr(result_sources, "load_full_result", lambda: {})

        r = client.get("/api/report/preview", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        assert r.json() == {"error": "분석 데이터가 없습니다."}

    def test_preview_with_real_generator_returns_html_and_markdown(
        self, monkeypatch, synthetic_data,
    ):
        """fake fixture 없이 실제 ReportGenerator 가 HTML/Markdown 을 생성해야 한다."""
        monkeypatch.setattr(db_service, "get_latest_analysis", lambda: synthetic_data)

        r = client.get("/api/report/preview", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body.keys()) == {"html", "markdown"}
        assert isinstance(body["html"], str) and "<html" in body["html"].lower()
        assert isinstance(body["markdown"], str) and body["markdown"].lstrip().startswith("#")


# ============================================================
# GET /api/report/generate
# ============================================================

class TestReportGenerate:
    def test_generate_no_data(
        self, monkeypatch, temp_reports_dir, fake_report_generator,
    ):
        """DB/JSON 모두 비어 있으면 error 메시지를 반환."""
        monkeypatch.setattr(db_service, "get_latest_analysis", lambda: None)
        monkeypatch.setattr(result_sources, "load_full_result", lambda: {})

        r = client.get("/api/report/generate", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        assert r.json() == {
            "error": "분석 데이터가 없습니다. 먼저 코드 분석을 실행하세요.",
        }

    def test_generate_db_data_response_shape(
        self, monkeypatch, temp_reports_dir, fake_report_generator, synthetic_data,
    ):
        """DB 데이터 + fake ReportGenerator 로 응답 셰이프 검증."""
        monkeypatch.setattr(db_service, "get_latest_analysis", lambda: synthetic_data)

        r = client.get("/api/report/generate?fmt=both", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "generated"
        assert set(data.keys()) == {"status", "files", "download_urls"}
        assert set(data["files"].keys()) == {"html", "md"}
        # 다운로드 URL 은 파일명만 사용해야 한다 (디렉터리 prefix 노출 X).
        assert data["download_urls"]["html"].startswith("/api/report/download/")
        assert data["download_urls"]["html"].endswith("report.html")
        assert data["download_urls"]["md"].endswith("report.md")
        # 실제 파일이 디스크에 생성되었는지도 확인.
        assert os.path.exists(os.path.join(temp_reports_dir, "report.html"))

    def test_generate_session_id_routes_to_session_loader(
        self, monkeypatch, temp_reports_dir, fake_report_generator, synthetic_data,
    ):
        """session_id 가 주어지면 get_analysis_by_session 이 호출된다."""
        called = {"by_session": 0, "latest": 0}

        def by_session(sid):
            called["by_session"] += 1
            assert sid == "abc123"
            return synthetic_data

        def latest():
            called["latest"] += 1
            return None

        monkeypatch.setattr(db_service, "get_analysis_by_session", by_session)
        monkeypatch.setattr(db_service, "get_latest_analysis", latest)

        r = client.get(
            "/api/report/generate?fmt=html&session_id=abc123",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["status"] == "generated"
        assert called == {"by_session": 1, "latest": 0}

    def test_generate_requires_auth(self):
        r = client.get("/api/report/generate")
        assert r.status_code in (401, 403)


# ============================================================
# GET /api/report/download/{filename}
# ============================================================

class TestReportDownload:
    def test_download_existing_html_file(self, temp_reports_dir):
        path = os.path.join(temp_reports_dir, "ok.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write("<html>ok</html>")

        r = client.get("/api/report/download/ok.html", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert r.text == "<html>ok</html>"

    def test_download_existing_md_file(self, temp_reports_dir):
        path = os.path.join(temp_reports_dir, "ok.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write("# ok")

        r = client.get("/api/report/download/ok.md", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/markdown")
        assert r.text == "# ok"

    def test_download_missing_returns_error_payload(self, temp_reports_dir):
        r = client.get(
            "/api/report/download/__nope__.html", headers=_AUTH_HEADERS,
        )
        assert r.status_code == 200
        assert r.json() == {"error": "리포트 파일을 찾을 수 없습니다."}

    def test_download_requires_auth(self):
        r = client.get("/api/report/download/anything.html")
        assert r.status_code in (401, 403)


# ============================================================
# GET /api/report/preview
# ============================================================

class TestReportPreview:
    def test_preview_no_data(self, monkeypatch, fake_report_generator):
        monkeypatch.setattr(db_service, "get_latest_analysis", lambda: None)
        monkeypatch.setattr(result_sources, "load_full_result", lambda: {})

        r = client.get("/api/report/preview", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        assert r.json() == {"error": "분석 데이터가 없습니다."}

    def test_preview_returns_html_and_markdown(
        self, monkeypatch, fake_report_generator, synthetic_data,
    ):
        monkeypatch.setattr(db_service, "get_latest_analysis", lambda: synthetic_data)

        r = client.get("/api/report/preview", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert set(data.keys()) == {"html", "markdown"}
        assert "fake-preview" in data["html"]
        assert "fake-preview" in data["markdown"]

    def test_preview_full_result_fallback(
        self, monkeypatch, fake_report_generator, synthetic_data,
    ):
        """DB가 비어 있어도 load_full_result 폴백이 동작."""
        monkeypatch.setattr(db_service, "get_latest_analysis", lambda: None)
        monkeypatch.setattr(result_sources, "load_full_result", lambda: synthetic_data)

        r = client.get("/api/report/preview", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "html" in data and "markdown" in data

    def test_preview_requires_auth(self):
        r = client.get("/api/report/preview")
        assert r.status_code in (401, 403)
