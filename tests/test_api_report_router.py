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
# Wave 2-Q — 다운로드 경로 헬퍼 / reports_path 일관 사용
# ============================================================
# 다운로드 라우터가 result_sources.reports_path 를 통해 경로를 계산하도록
# 하드닝한다. 직접 os.path.join(REPORTS_DIR, ...) 호출이 흩어지지 않도록
# 단일 진입점으로 모은 뒤 sanitize 동작도 함께 회귀 테스트한다.

class TestSafeReportFilenameHelper:
    """_safe_report_filename 헬퍼의 존재와 동작을 보증한다."""

    def test_helper_exists(self):
        from api.routers import report

        assert hasattr(report, "_safe_report_filename"), (
            "report 라우터에 _safe_report_filename 헬퍼가 있어야 한다"
        )

    def test_helper_replaces_forward_slashes(self):
        from api.routers.report import _safe_report_filename

        assert _safe_report_filename("a/b.html") == "a_b.html"

    def test_helper_replaces_backslashes(self):
        from api.routers.report import _safe_report_filename

        assert _safe_report_filename("a\\b.html") == "a_b.html"

    def test_helper_replaces_traversal_segment(self):
        """``../secret`` 형태가 들어와도 슬래시가 _ 로 치환되어
        디렉터리 밖을 가리키지 않게 만든다 (현재 동작 보존)."""
        from api.routers.report import _safe_report_filename

        # '../secret.html' → '.._secret.html' (현재 inline 로직과 동일)
        assert _safe_report_filename("../secret.html") == ".._secret.html"

    def test_helper_passthrough_for_simple_filename(self):
        from api.routers.report import _safe_report_filename

        assert _safe_report_filename("report.html") == "report.html"


class TestDownloadUsesReportsPathHelper:
    """download_report 가 ``result_sources.reports_path`` 를 통해 경로를 계산해야 한다.

    REPORTS_DIR 만 직접 참조하는 inline ``os.path.join`` 호출이 남아 있으면,
    아래의 ``reports_path`` monkeypatch 가 효과를 보지 못해 테스트가 실패한다.
    """

    def test_download_routes_through_reports_path(
        self, monkeypatch, tmp_path,
    ):
        redirect_dir = tmp_path / "redirect"
        redirect_dir.mkdir()
        (redirect_dir / "ok.html").write_text(
            "<html>redirected</html>", encoding="utf-8",
        )

        recorded: list[str] = []

        def fake_reports_path(filename: str) -> str:
            recorded.append(filename)
            return str(redirect_dir / filename)

        # REPORTS_DIR 은 빈 다른 디렉터리로 두어, reports_path 헬퍼를
        # 거치지 않으면 파일을 못 찾도록 한다.
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.setattr(result_sources, "REPORTS_DIR", str(elsewhere))
        monkeypatch.setattr(result_sources, "reports_path", fake_reports_path)

        r = client.get(
            "/api/report/download/ok.html", headers=_AUTH_HEADERS,
        )
        assert r.status_code == 200
        assert r.text == "<html>redirected</html>"
        assert recorded == ["ok.html"]

    def test_download_passes_sanitized_name_to_reports_path(
        self, monkeypatch, tmp_path,
    ):
        """슬래시가 포함된 입력은 sanitize 된 형태로 reports_path 에 전달된다."""
        target_dir = tmp_path / "redir2"
        target_dir.mkdir()

        recorded: list[str] = []

        def fake_reports_path(filename: str) -> str:
            recorded.append(filename)
            return str(target_dir / filename)

        monkeypatch.setattr(result_sources, "REPORTS_DIR", str(target_dir))
        monkeypatch.setattr(result_sources, "reports_path", fake_reports_path)

        # 함수 직접 호출 — FastAPI 의 path 매칭 동작에 의존하지 않는다.
        from api.routers.report import download_report

        result = download_report("a\\b.html")
        # 파일이 존재하지 않으므로 missing 응답이지만, sanitize 된 이름으로
        # reports_path 가 호출되었어야 한다.
        assert result == {"error": "리포트 파일을 찾을 수 없습니다."}
        assert recorded == ["a_b.html"]

    def test_download_traversal_sanitized_stays_in_dir(
        self, monkeypatch, tmp_path,
    ):
        """디렉터리 밖에 있는 secret.html 은 sanitize 후 접근 불가능하다.

        ``../secret.html`` 같은 입력은 슬래시가 _ 로 치환되어
        ``.._secret.html`` 이 된다. REPORTS_DIR 안에 그 파일이 없는 한
        missing 응답이 되어야 하고, 디렉터리 밖의 진짜 secret.html 은
        절대 읽히지 않는다.
        """
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        # 디렉터리 밖에 진짜 secret 파일 배치 — 읽히면 안 된다.
        outside = tmp_path / "secret.html"
        outside.write_text("<html>SECRET</html>", encoding="utf-8")

        monkeypatch.setattr(result_sources, "REPORTS_DIR", str(reports_dir))

        from api.routers.report import download_report

        result = download_report("../secret.html")
        assert result == {"error": "리포트 파일을 찾을 수 없습니다."}


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
