"""대시보드 조회 서비스 단위 테스트 (tests/test_api_dashboard_queries_service.py).

Wave 2-M: ``api/routers/dashboard.py`` 에 들어 있던 read-only 비즈니스 로직
(stats DB-우선/JSON 폴백, Bandit 폴백 변환, 필터링, by-file/by-type 집계,
 패치 enrichment, sessions 조회) 을 ``api.services.dashboard_queries`` 로
분리한 모듈에 대한 단위 테스트.

원칙:
  - 서비스 모듈은 ``api.server`` / FastAPI / ``Depends`` / ``APIRouter`` /
    응답 DTO 를 import 하지 않는다 (HTTP 비의존).
  - 라우터 본문은 서비스에 위임하고, ``db_service.*`` / ``result_sources.*``
    및 변환/집계 루프를 직접 포함하지 않는다.
  - 단위 테스트는 monkeypatch 로 ``result_sources`` / ``db_service`` 를
    fake 처리하여 네트워크/시크릿 없이 동작한다.
"""

from __future__ import annotations

import ast
import inspect

import pytest


# ============================================================
# Import surface — 서비스 모듈은 HTTP 계층 의존이 없어야 한다
# ============================================================

class TestServiceImportSurface:
    FORBIDDEN_TOP_LEVEL = {
        "fastapi",
        "fastapi.params",
        "api.server",
        "api.dto.responses",
    }

    def _module_source(self) -> str:
        from api.services import dashboard_queries as svc

        return inspect.getsource(svc)

    def test_module_does_not_import_api_server(self):
        tree = ast.parse(self._module_source())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name != "api.server", "api.server 직접 import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "api.server", "from api.server import 금지"

    def test_module_does_not_import_fastapi_or_dtos(self):
        tree = ast.parse(self._module_source())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name not in self.FORBIDDEN_TOP_LEVEL, (
                        f"서비스 모듈에서 {n.name} import 금지"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                base = node.module.split(".")[0]
                assert base != "fastapi", "서비스 모듈에서 fastapi import 금지"
                assert node.module != "api.dto.responses", (
                    "서비스 모듈에서 응답 DTO import 금지"
                )

    def test_module_does_not_reference_apirouter_or_depends(self):
        src = self._module_source()
        assert "APIRouter" not in src, "서비스 모듈에서 APIRouter 사용 금지"
        assert "Depends(" not in src, "서비스 모듈에서 Depends 사용 금지"
        assert "Query(" not in src, "서비스 모듈에서 Query 사용 금지"


# ============================================================
# 서비스 함수 노출
# ============================================================

class TestServiceFunctionsExposed:
    def test_exports_required_callables(self):
        from api.services import dashboard_queries as svc

        for name in (
            "get_stats",
            "get_vulnerabilities",
            "get_vulnerabilities_by_file",
            "get_vulnerabilities_by_type",
            "get_patches",
            "get_sessions",
            "get_session_detail",
        ):
            assert callable(getattr(svc, name, None)), (
                f"서비스 모듈이 {name} 콜러블을 노출해야 함"
            )


# ============================================================
# get_stats — DB 우선 / JSON 폴백 / Bandit 폴백
# ============================================================

class TestGetStatsService:
    def test_db_first_when_total_issues_positive(self, monkeypatch):
        from api.services import dashboard_queries as svc

        db_payload = {
            "total_issues": 5, "high": 2, "medium": 2, "low": 1,
            "patches_generated": 3, "patches_verified": 2,
            "session_id": "sess-db", "total_sessions": 7,
        }
        monkeypatch.setattr(svc.db_service, "get_stats", lambda: db_payload)
        # JSON 폴백이 절대 호출되지 않아야 한다
        monkeypatch.setattr(
            svc.result_sources, "load_full_result",
            lambda: pytest.fail("DB-first 경로에서 JSON 폴백 호출 금지"),
        )
        monkeypatch.setattr(
            svc.result_sources, "load_bandit_report",
            lambda: pytest.fail("DB-first 경로에서 Bandit 폴백 호출 금지"),
        )

        result = svc.get_stats()
        assert result == db_payload

    def test_full_result_fallback_when_db_empty(self, monkeypatch):
        from api.services import dashboard_queries as svc

        monkeypatch.setattr(
            svc.db_service, "get_stats",
            lambda: {
                "total_issues": 0, "high": 0, "medium": 0, "low": 0,
                "patches_generated": 0, "patches_verified": 0,
            },
        )
        monkeypatch.setattr(
            svc.result_sources, "load_full_result",
            lambda: {
                "summary": {
                    "total": 4, "high": 1, "medium": 2, "low": 1,
                    "patches_generated": 2, "patches_verified": 1,
                },
                "duration_seconds": 9.0,
                "session_id": "sess-json",
            },
        )

        result = svc.get_stats()
        assert result["total_issues"] == 4
        assert result["high"] == 1
        assert result["medium"] == 2
        assert result["low"] == 1
        assert result["patches_generated"] == 2
        assert result["patches_verified"] == 1
        assert result["duration_seconds"] == 9.0
        assert result["session_id"] == "sess-json"

    def test_bandit_fallback_when_db_and_full_empty(self, monkeypatch):
        from api.services import dashboard_queries as svc

        monkeypatch.setattr(
            svc.db_service, "get_stats",
            lambda: {
                "total_issues": 0, "high": 0, "medium": 0, "low": 0,
                "patches_generated": 0, "patches_verified": 0,
            },
        )
        monkeypatch.setattr(svc.result_sources, "load_full_result", lambda: {})
        monkeypatch.setattr(
            svc.result_sources, "load_bandit_report",
            lambda: {
                "results": [{"test_id": "B1"}, {"test_id": "B2"}],
                "metrics": {"_totals": {
                    "SEVERITY.HIGH": 1, "SEVERITY.MEDIUM": 1, "SEVERITY.LOW": 0,
                }},
            },
        )

        result = svc.get_stats()
        assert result["total_issues"] == 2
        assert result["high"] == 1
        assert result["medium"] == 1
        assert result["low"] == 0
        assert result["patches_generated"] == 0
        assert result["patches_verified"] == 0


# ============================================================
# get_vulnerabilities — 필터링 / Bandit 폴백 변환 (CWE 포맷)
# ============================================================

class TestGetVulnerabilitiesService:
    def test_filters_severity_tool_file_path(self, monkeypatch):
        from api.services import dashboard_queries as svc

        full = {
            "vulnerabilities": [
                {"id": "v1", "tool": "bandit", "severity": "HIGH",
                 "file_path": "app/main.py", "rule_id": "B608", "title": "SQLi"},
                {"id": "v2", "tool": "bandit", "severity": "LOW",
                 "file_path": "app/main.py", "rule_id": "B101", "title": "Assert"},
                {"id": "v3", "tool": "sonarqube", "severity": "HIGH",
                 "file_path": "lib/util.py", "rule_id": "S100", "title": "X"},
            ],
        }
        monkeypatch.setattr(svc.result_sources, "load_full_result", lambda: full)

        only_high = svc.get_vulnerabilities(severity="HIGH")
        assert only_high["count"] == 2
        assert {v["id"] for v in only_high["vulnerabilities"]} == {"v1", "v3"}

        only_bandit = svc.get_vulnerabilities(tool="bandit")
        assert only_bandit["count"] == 2
        assert {v["id"] for v in only_bandit["vulnerabilities"]} == {"v1", "v2"}

        only_main = svc.get_vulnerabilities(file_path="app/main.py")
        assert only_main["count"] == 2
        assert {v["id"] for v in only_main["vulnerabilities"]} == {"v1", "v2"}

        # case-insensitive severity / tool 필터
        ci = svc.get_vulnerabilities(severity="high", tool="BANDIT")
        assert {v["id"] for v in ci["vulnerabilities"]} == {"v1"}

    def test_bandit_fallback_cwe_formatting(self, monkeypatch):
        from api.services import dashboard_queries as svc

        # full_result 가 비었거나 vulnerabilities 키가 비어 있을 때 Bandit 폴백
        monkeypatch.setattr(svc.result_sources, "load_full_result", lambda: {})
        monkeypatch.setattr(
            svc.result_sources, "load_bandit_report",
            lambda: {
                "results": [
                    {
                        "test_id": "B608",
                        "test_name": "SQLi",
                        "issue_severity": "HIGH",
                        "issue_confidence": "HIGH",
                        "issue_text": "f-string SQL",
                        "filename": "app.py",
                        "line_number": 7,
                        "code": "query = f'...'",
                        "issue_cwe": {"id": 89},
                        "more_info": "https://example.test/B608",
                    },
                    {
                        "test_id": "B101",
                        "test_name": "Assert",
                        "issue_severity": "LOW",
                        "issue_confidence": "LOW",
                        "issue_text": "assert used",
                        "filename": "u.py",
                        "line_number": 1,
                        "code": "assert x",
                        # CWE 가 없는 경우
                        "issue_cwe": {},
                        "more_info": "",
                    },
                ],
                "metrics": {"_totals": {}},
            },
        )

        result = svc.get_vulnerabilities()
        assert result["count"] == 2
        items_by_id = {v["id"]: v for v in result["vulnerabilities"]}
        assert "vuln_B608_7" in items_by_id
        assert items_by_id["vuln_B608_7"]["cwe_id"] == "CWE-89"
        # 누락 CWE 는 None 으로 표기
        assert items_by_id["vuln_B101_1"]["cwe_id"] is None
        # tool 필드는 기본값 "bandit"
        assert all(v["tool"] == "bandit" for v in result["vulnerabilities"])


# ============================================================
# by-file / by-type 집계
# ============================================================

class TestAggregationService:
    def test_by_file_aggregation(self, monkeypatch):
        from api.services import dashboard_queries as svc

        full = {
            "vulnerabilities": [
                {"id": "v1", "tool": "bandit", "severity": "HIGH",
                 "file_path": "a.py", "rule_id": "R1", "title": "T1"},
                {"id": "v2", "tool": "bandit", "severity": "MEDIUM",
                 "file_path": "a.py", "rule_id": "R2", "title": "T2"},
                {"id": "v3", "tool": "bandit", "severity": "LOW",
                 "file_path": "b.py", "rule_id": "R3", "title": "T3"},
                {"id": "v4", "tool": "bandit", "severity": "HIGH",
                 "file_path": "b.py", "rule_id": "R4", "title": "T4"},
            ],
        }
        monkeypatch.setattr(svc.result_sources, "load_full_result", lambda: full)

        result = svc.get_vulnerabilities_by_file()
        files = {f["file"]: f for f in result["files"]}
        assert files["a.py"] == {"file": "a.py", "high": 1, "medium": 1, "low": 0, "total": 2}
        assert files["b.py"] == {"file": "b.py", "high": 1, "medium": 0, "low": 1, "total": 2}

    def test_by_type_aggregation(self, monkeypatch):
        from api.services import dashboard_queries as svc

        full = {
            "vulnerabilities": [
                {"id": "v1", "tool": "bandit", "severity": "HIGH",
                 "file_path": "a.py", "rule_id": "B608", "title": "SQLi"},
                {"id": "v2", "tool": "bandit", "severity": "HIGH",
                 "file_path": "b.py", "rule_id": "B608", "title": "SQLi"},
                {"id": "v3", "tool": "bandit", "severity": "LOW",
                 "file_path": "c.py", "rule_id": "B101", "title": "Assert"},
            ],
        }
        monkeypatch.setattr(svc.result_sources, "load_full_result", lambda: full)

        result = svc.get_vulnerabilities_by_type()
        types_by_key = {(t["rule_id"], t["name"]): t for t in result["types"]}
        assert types_by_key[("B608", "SQLi")]["count"] == 2
        assert types_by_key[("B608", "SQLi")]["severity"] == "HIGH"
        assert types_by_key[("B101", "Assert")]["count"] == 1


# ============================================================
# patches enrichment
# ============================================================

class TestGetPatchesService:
    def test_patch_enriched_with_function_code_when_present(self, monkeypatch):
        from api.services import dashboard_queries as svc

        full = {
            "vulnerabilities": [
                {
                    "id": "v1", "tool": "bandit", "severity": "HIGH",
                    "file_path": "a.py", "line_number": 10, "rule_id": "B608",
                    "title": "SQLi",
                    "function_code": "def f(): ...",
                    "code_snippet": "snippet",
                },
            ],
            "patches": [
                {
                    "vulnerability_id": "v1", "fixed_code": "fix",
                    "explanation": "x", "fix_type": "recommended",
                    "status": "verified",
                },
            ],
        }
        monkeypatch.setattr(svc.result_sources, "load_full_result", lambda: full)

        result = svc.get_patches()
        assert result["count"] == 1
        p = result["patches"][0]
        assert p["file_path"] == "a.py"
        assert p["line_number"] == 10
        assert p["rule_id"] == "B608"
        assert p["severity"] == "HIGH"
        assert p["title"] == "SQLi"
        # function_code 가 있으면 우선
        assert p["original_code"] == "def f(): ..."

    def test_patch_falls_back_to_code_snippet_when_no_function_code(self, monkeypatch):
        from api.services import dashboard_queries as svc

        full = {
            "vulnerabilities": [
                {
                    "id": "v1", "tool": "bandit", "severity": "MEDIUM",
                    "file_path": "u.py", "line_number": 3, "rule_id": "B101",
                    "title": "Assert",
                    # function_code 누락
                    "code_snippet": "assert x",
                },
            ],
            "patches": [
                {
                    "vulnerability_id": "v1", "fixed_code": "if not x: raise",
                    "explanation": "use exception",
                    "fix_type": "recommended", "status": "verified",
                },
            ],
        }
        monkeypatch.setattr(svc.result_sources, "load_full_result", lambda: full)

        result = svc.get_patches()
        p = result["patches"][0]
        assert p["original_code"] == "assert x"


# ============================================================
# sessions / session detail
# ============================================================

class TestSessionsService:
    def test_get_sessions_returns_count_and_sessions(self, monkeypatch):
        from api.services import dashboard_queries as svc

        sessions = [{"session_id": "s1"}, {"session_id": "s2"}]
        monkeypatch.setattr(svc.db_service, "get_all_sessions", lambda: sessions)
        result = svc.get_sessions()
        assert result == {"count": 2, "sessions": sessions}

    def test_session_detail_returns_dict_when_found(self, monkeypatch):
        from api.services import dashboard_queries as svc

        payload = {"session_id": "s1", "summary": {"total": 1}}
        monkeypatch.setattr(
            svc.db_service, "get_analysis_by_session", lambda sid: payload,
        )
        assert svc.get_session_detail("s1") == payload

    def test_session_detail_returns_error_when_missing(self, monkeypatch):
        from api.services import dashboard_queries as svc

        monkeypatch.setattr(
            svc.db_service, "get_analysis_by_session", lambda sid: None,
        )
        assert svc.get_session_detail("missing") == {"error": "Session not found"}


# ============================================================
# 라우터는 비즈니스 로직을 서비스 모듈에 위임해야 한다
# ============================================================

class TestRouterDelegatesToService:
    """라우터 본문에서 ``db_service.*`` / ``result_sources.load_*`` 직접 호출과
    변환/집계 루프가 사라져야 한다.
    """

    def _endpoint_source(self, name: str) -> str:
        import api.routers.dashboard as mod

        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == name:
                return ast.unparse(node)
        raise AssertionError(f"{name} 엔드포인트를 찾을 수 없음")

    @pytest.mark.parametrize("name", [
        "get_stats",
        "get_vulnerabilities",
        "get_vulnerabilities_by_file",
        "get_vulnerabilities_by_type",
        "get_patches",
        "get_sessions",
        "get_session_detail",
    ])
    def test_endpoint_does_not_call_db_service_or_result_sources(self, name):
        src = self._endpoint_source(name)
        assert "db_service." not in src, (
            f"{name}: 라우터에서 db_service.* 직접 호출 금지 — 서비스에 위임"
        )
        assert "result_sources." not in src, (
            f"{name}: 라우터에서 result_sources.* 직접 호출 금지 — 서비스에 위임"
        )

    def test_router_module_does_not_import_db_service_or_result_sources(self):
        import api.routers.dashboard as mod

        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                # `from db import service as db_service` 패턴 차단
                if node.module == "db":
                    for n in node.names:
                        assert n.name != "service", (
                            "라우터에서 db.service 직접 import 금지"
                        )
                if node.module == "api":
                    for n in node.names:
                        assert n.name != "result_sources", (
                            "라우터에서 api.result_sources 직접 import 금지"
                        )
                if node.module in ("db.service", "api.result_sources"):
                    raise AssertionError(
                        f"라우터에서 {node.module} 직접 import 금지"
                    )

    def test_router_does_not_contain_aggregation_loops(self):
        """집계/변환 루프가 라우터 함수 본문에서 사라졌는지 확인."""
        for name in (
            "get_vulnerabilities", "get_vulnerabilities_by_file",
            "get_vulnerabilities_by_type", "get_patches",
        ):
            src = self._endpoint_source(name)
            # 변환/집계 흔적 — 어떤 라우터든 이런 키워드가 본문에 있으면
            # 비즈니스 로직이 라우터에 남아 있다는 뜻이다.
            assert "issue_cwe" not in src, (
                f"{name}: bandit fallback 변환은 서비스에 있어야 함"
            )
            assert "file_counts" not in src, (
                f"{name}: by-file 집계는 서비스에 있어야 함"
            )
            assert "type_counts" not in src, (
                f"{name}: by-type 집계는 서비스에 있어야 함"
            )
            assert "function_code" not in src, (
                f"{name}: patch enrichment 는 서비스에 있어야 함"
            )
