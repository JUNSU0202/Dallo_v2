"""Red/Blue 요약 API 라우터/서비스 테스트 (tests/test_api_red_blue_router.py).

Wave 5-C: ``shared.red_blue.build_red_blue_summary`` 를 인증된 API
엔드포인트 ``GET /api/red-blue/summary`` 로 노출하는 라우터/서비스
계층의 단위 + 라우터 통합 테스트.

원칙:
  - 서비스 모듈은 FastAPI / Pydantic / ``api.server`` 의존을 갖지 않는다.
  - 라우터는 얇은 위임만 담당하며 서비스 함수를 호출한다.
  - 데이터 소스 우선순위: DB → JSON 폴백 → 빈 셰이프 (모두 실패해도 500 X).
  - 모든 외부 의존(DB / JSON 로더) 은 monkeypatch / fake 로만 호출된다.
"""

from __future__ import annotations

import ast
import inspect
import os

os.environ["DALLO_API_KEYS"] = "test-api-key"
os.environ.setdefault("DALLO_ENCRYPTION_KEY", "test-key")

import pytest
from fastapi.testclient import TestClient

from api.server import app


_AUTH_HEADERS = {"X-API-Key": "test-api-key"}
_EXPECTED_TOP_KEYS = {"red_team", "blue_team", "comparison", "attack_paths"}


# ============================================================
# 인증 / 라우트 등록
# ============================================================

class TestAuthAndRegistration:
    def test_endpoint_is_registered_on_app(self):
        """/api/red-blue/summary 가 app.routes 에 등록되어 있어야 한다."""
        paths = {getattr(r, "path", None) for r in app.routes}
        assert "/api/red-blue/summary" in paths, (
            f"라우트 미등록 — 실제 등록된 경로 일부: "
            f"{sorted(p for p in paths if isinstance(p, str) and '/api/' in p)}"
        )

    def test_missing_api_key_is_rejected(self, monkeypatch):
        """X-API-Key 없이 호출하면 401/403 — DALLO_API_KEYS 가 세팅된 컨텍스트."""
        monkeypatch.setenv("DALLO_API_KEYS", "test-api-key")
        client = TestClient(app)
        r = client.get("/api/red-blue/summary")
        assert r.status_code in (401, 403), (
            f"인증 누락 시 401/403 기대했으나 {r.status_code}: {r.text}"
        )


# ============================================================
# 서비스 import surface — HTTP 계층 의존 금지
# ============================================================

class TestServiceImportSurface:
    FORBIDDEN_TOP_LEVEL = {"fastapi", "fastapi.params", "api.server"}

    def _module_source(self) -> str:
        from api.services import red_blue_summary as svc

        return inspect.getsource(svc)

    def test_module_does_not_import_fastapi(self):
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
                assert node.module != "api.server", (
                    "서비스 모듈에서 api.server import 금지"
                )

    def test_module_does_not_import_pydantic(self):
        src = self._module_source()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name != "pydantic", (
                        "서비스 모듈에서 pydantic import 금지"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                base = node.module.split(".")[0]
                assert base != "pydantic", (
                    "서비스 모듈에서 pydantic import 금지"
                )

    def test_module_does_not_reference_apirouter_or_depends(self):
        src = self._module_source()
        assert "APIRouter" not in src, "서비스 모듈에서 APIRouter 사용 금지"
        assert "Depends(" not in src, "서비스 모듈에서 Depends 사용 금지"


# ============================================================
# 서비스 단위 — DB 우선 / JSON 폴백 / 빈 셰이프
# ============================================================

def _full_result_payload() -> dict:
    return {
        "vulnerabilities": [
            {
                "id": "vuln_B608_10",
                "tool": "bandit",
                "rule_id": "B608",
                "severity": "HIGH",
                "cwe_id": "CWE-89",
                "title": "SQLi",
                "file_path": "app.py",
                "line_number": 10,
                "code_snippet": "query = f'...'",
                "function_code": "def get(): ...",
            },
        ],
        "patches": [
            {
                "vulnerability_id": "vuln_B608_10",
                "fixed_code": "cur.execute('SELECT * FROM u WHERE id=%s', (uid,))",
                "explanation": "bind params",
                "fix_type": "recommended",
                "status": "verified",
                "syntax_valid": True,
                "security_revalidation": {"passed": True, "introduced_count": 0,
                                           "removed_count": 1},
            },
        ],
    }


class TestServiceDataSourceOrder:
    def test_db_first_skips_json_fallback(self, monkeypatch):
        from api.services import red_blue_summary as svc

        payload = _full_result_payload()
        monkeypatch.setattr(
            svc.db_service, "get_latest_analysis", lambda: payload,
        )
        # JSON 폴백이 호출되면 즉시 실패
        monkeypatch.setattr(
            svc.result_sources, "load_full_result",
            lambda: pytest.fail("DB-first 경로에서 JSON 폴백 호출 금지"),
        )

        result = svc.get_red_blue_summary()
        assert set(result) == _EXPECTED_TOP_KEYS
        assert result["red_team"]["total_findings"] == 1
        assert result["red_team"]["critical_or_high"] == 1
        assert result["blue_team"]["patches_generated"] == 1
        assert result["blue_team"]["patches_verified"] == 1
        assert isinstance(result["attack_paths"], list)
        assert result["comparison"]["before_total"] == 1

    def test_json_fallback_when_db_returns_none(self, monkeypatch):
        from api.services import red_blue_summary as svc

        payload = _full_result_payload()
        monkeypatch.setattr(svc.db_service, "get_latest_analysis", lambda: None)
        monkeypatch.setattr(
            svc.result_sources, "load_full_result", lambda: payload,
        )

        result = svc.get_red_blue_summary()
        assert set(result) == _EXPECTED_TOP_KEYS
        assert result["red_team"]["total_findings"] == 1
        assert result["blue_team"]["patches_verified"] == 1

    def test_empty_shape_when_db_and_json_both_fail(self, monkeypatch):
        from api.services import red_blue_summary as svc

        def _boom_db():
            raise RuntimeError("DB explode")

        def _boom_json():
            raise OSError("disk explode")

        monkeypatch.setattr(svc.db_service, "get_latest_analysis", _boom_db)
        monkeypatch.setattr(svc.result_sources, "load_full_result", _boom_json)

        result = svc.get_red_blue_summary()
        assert set(result) == _EXPECTED_TOP_KEYS
        # 빈 셰이프: 0/빈 리스트
        assert result["red_team"]["total_findings"] == 0
        assert result["red_team"]["critical_or_high"] == 0
        assert result["blue_team"]["patches_generated"] == 0
        assert result["blue_team"]["patches_verified"] == 0
        assert result["attack_paths"] == []
        assert result["comparison"]["before_total"] == 0

    def test_empty_shape_when_db_and_json_both_absent(self, monkeypatch):
        from api.services import red_blue_summary as svc

        monkeypatch.setattr(svc.db_service, "get_latest_analysis", lambda: None)
        monkeypatch.setattr(svc.result_sources, "load_full_result", lambda: {})

        result = svc.get_red_blue_summary()
        assert set(result) == _EXPECTED_TOP_KEYS
        assert result["red_team"]["total_findings"] == 0
        assert result["attack_paths"] == []

    def test_non_list_vulnerabilities_normalized_to_empty(self, monkeypatch):
        """소스 dict 의 vulnerabilities/patches 가 list 가 아니면 빈 리스트로 폴백."""
        from api.services import red_blue_summary as svc

        broken = {"vulnerabilities": "not-a-list", "patches": None}
        monkeypatch.setattr(svc.db_service, "get_latest_analysis", lambda: broken)
        monkeypatch.setattr(
            svc.result_sources, "load_full_result",
            lambda: pytest.fail("DB-first 경로에서 JSON 폴백 호출 금지"),
        )

        result = svc.get_red_blue_summary()
        assert set(result) == _EXPECTED_TOP_KEYS
        assert result["red_team"]["total_findings"] == 0
        assert result["attack_paths"] == []


# ============================================================
# HTTP 통합 — 응답 셰이프 / DB-first / JSON 폴백 / 빈 폴백
# ============================================================

class TestEndpointResponseShape:
    def test_endpoint_returns_full_top_level_keys(self, monkeypatch):
        from api.services import red_blue_summary as svc

        payload = _full_result_payload()
        monkeypatch.setattr(svc.db_service, "get_latest_analysis", lambda: payload)
        # JSON 폴백이 사용되면 실패
        monkeypatch.setattr(
            svc.result_sources, "load_full_result",
            lambda: pytest.fail("DB-first 경로에서 JSON 폴백 호출 금지"),
        )

        client = TestClient(app)
        r = client.get("/api/red-blue/summary", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body.keys()) == _EXPECTED_TOP_KEYS, (
            f"top-level 키 집합 불일치: {sorted(body.keys())}"
        )

    def test_endpoint_uses_json_when_db_missing(self, monkeypatch):
        from api.services import red_blue_summary as svc

        monkeypatch.setattr(svc.db_service, "get_latest_analysis", lambda: None)
        monkeypatch.setattr(
            svc.result_sources, "load_full_result", lambda: _full_result_payload(),
        )

        client = TestClient(app)
        r = client.get("/api/red-blue/summary", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert set(body.keys()) == _EXPECTED_TOP_KEYS
        assert body["red_team"]["total_findings"] == 1

    def test_endpoint_returns_empty_shape_on_both_failures(self, monkeypatch):
        from api.services import red_blue_summary as svc

        monkeypatch.setattr(
            svc.db_service, "get_latest_analysis",
            lambda: (_ for _ in ()).throw(RuntimeError("db down")),
        )
        monkeypatch.setattr(
            svc.result_sources, "load_full_result",
            lambda: (_ for _ in ()).throw(OSError("json broken")),
        )

        client = TestClient(app)
        r = client.get("/api/red-blue/summary", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body.keys()) == _EXPECTED_TOP_KEYS
        assert body["red_team"]["total_findings"] == 0
        assert body["blue_team"]["patches_generated"] == 0
        assert body["attack_paths"] == []
        assert body["comparison"]["before_total"] == 0


# ============================================================
# 라우터는 서비스에 위임해야 한다 (얇은 라우터)
# ============================================================

class TestRouterDelegatesToService:
    def test_route_returns_value_from_service(self, monkeypatch):
        """라우터는 서비스 결과를 그대로 전달해야 한다."""
        from api.services import red_blue_summary as svc

        fake_result = {
            "red_team": {"total_findings": 7, "critical_or_high": 3,
                          "unique_cwe": 2, "affected_files": 4},
            "blue_team": {"patches_generated": 5, "patches_verified": 2,
                           "patches_needing_review": 1},
            "comparison": {"before_total": 7, "after_total": 5,
                            "fixed_count": 2, "remaining_count": 5,
                            "introduced_count": 0,
                            "risk_reduction_percent": 28.6},
            "attack_paths": [{"finding_id": "f1"}],
        }
        monkeypatch.setattr(
            svc, "get_red_blue_summary", lambda *a, **kw: fake_result,
        )

        client = TestClient(app)
        r = client.get("/api/red-blue/summary", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        body = r.json()
        # 라우터가 서비스 결과를 그대로 반환해야 함
        assert body == fake_result

    def test_router_body_does_not_contain_business_logic(self):
        """라우터 본문에서 build_red_blue_summary / db_service / result_sources
        호출이 등장하면 안 된다 — 모두 서비스에 위임해야 한다."""
        from api.routers import red_blue as router_mod

        tree = ast.parse(inspect.getsource(router_mod))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                body_src = ast.unparse(node)
                assert "build_red_blue_summary" not in body_src, (
                    f"{node.name}: 라우터에서 shared.red_blue 직접 호출 금지"
                )
                assert "db_service." not in body_src, (
                    f"{node.name}: 라우터에서 db_service.* 직접 호출 금지"
                )
                assert "result_sources." not in body_src, (
                    f"{node.name}: 라우터에서 result_sources.* 직접 호출 금지"
                )


# ============================================================
# 서비스 함수 노출
# ============================================================

class TestServiceFunctionExposed:
    def test_exports_get_red_blue_summary_callable(self):
        from api.services import red_blue_summary as svc

        assert callable(getattr(svc, "get_red_blue_summary", None)), (
            "서비스 모듈이 get_red_blue_summary 콜러블을 노출해야 함"
        )
