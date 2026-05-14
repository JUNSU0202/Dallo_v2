"""Wave 5-D — 대시보드 응답에 Red/Blue 키가 additive 로 부착되는지 검증.

본 테스트는 다음을 동결한다:

- ``api/services/red_blue_view.py`` 는 HTTP/Pydantic 의존이 없는 순수 서비스다.
- ``api.services.dashboard_queries.get_vulnerabilities`` / ``get_patches`` /
  ``get_stats`` / ``get_session_detail`` 는 *기존 키를 보존하면서* Red/Blue
  enrichment 키를 추가만 한다.
- ``api/routers/dashboard.py`` 의 ``response_model_exclude_unset=True`` +
  ``_Permissive(extra="allow")`` 조합에 의해 추가 키가 응답에 그대로 통과된다.
- ``get_stats`` 의 빈 폴백은 정확히 6개 키만 유지한다 (기존 회귀 가드 보존).
"""

from __future__ import annotations

import ast
import inspect
import os

os.environ["DALLO_API_KEYS"] = "test-api-key"
os.environ.setdefault("DALLO_ENCRYPTION_KEY", "test-key")

from fastapi.testclient import TestClient

from api import result_sources
from api.server import app


_AUTH_HEADERS = {"X-API-Key": "test-api-key"}

_RED_KEYS = {
    "red_team_phase",
    "attack_vector",
    "attack_scenario",
    "security_impact",
    "blue_team_strategy",
    "exploitability",
    "attack_plan",
}
_BLUE_KEYS = {
    "blue_team_phase",
    "defense_strategy",
    "defense_outcome",
    "residual_risk",
    "defense_plan",
}
_SUMMARY_TOP_KEYS = {"red_team", "blue_team", "comparison", "attack_paths"}


def _sample_full_result() -> dict:
    return {
        "vulnerabilities": [
            {
                "id": "vuln_B608_10",
                "tool": "bandit",
                "rule_id": "B608",
                "severity": "HIGH",
                "confidence": "HIGH",
                "cwe_id": "CWE-89",
                "title": "SQL Injection",
                "description": "f-string SQL",
                "file_path": "app.py",
                "line_number": 10,
                "code_snippet": "query = f'SELECT * FROM u WHERE id={uid}'",
                "function_code": "def get(): query = f'SELECT * FROM u WHERE id={uid}'",
                "more_info": "https://example.test/B608",
            },
            {
                "id": "vuln_B303_30",
                "tool": "bandit",
                "rule_id": "B303",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "cwe_id": "CWE-328",
                "title": "Weak Hash",
                "description": "MD5",
                "file_path": "util.py",
                "line_number": 30,
                "code_snippet": "hashlib.md5(data)",
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
                "security_revalidation": {
                    "passed": True,
                    "introduced_count": 0,
                    "removed_count": 1,
                },
            },
        ],
        "summary": {
            "total": 2,
            "high": 1,
            "medium": 1,
            "low": 0,
            "patches_generated": 1,
            "patches_verified": 1,
        },
        "duration_seconds": 1.0,
        "session_id": "sess-w5d",
    }


# ============================================================
# 1. red_blue_view import surface
# ============================================================


class TestRedBlueViewImportSurface:
    FORBIDDEN_TOP_LEVEL = {"fastapi", "fastapi.params", "api.server", "pydantic"}

    def _module_source(self) -> str:
        from api.services import red_blue_view as svc

        return inspect.getsource(svc)

    def test_module_does_not_import_fastapi_or_pydantic_or_api_server(self):
        tree = ast.parse(self._module_source())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name not in self.FORBIDDEN_TOP_LEVEL, (
                        f"red_blue_view 가 {n.name} 을 import 하면 안 된다"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                base = node.module.split(".")[0]
                assert base not in ("fastapi", "pydantic"), (
                    f"red_blue_view 가 {node.module} 을 import 하면 안 된다"
                )
                assert node.module != "api.server", (
                    "red_blue_view 가 api.server 를 import 하면 안 된다"
                )

    def test_module_does_not_reference_apirouter_or_depends_or_query(self):
        src = self._module_source()
        assert "APIRouter" not in src, "red_blue_view 안에서 APIRouter 금지"
        assert "Depends(" not in src, "red_blue_view 안에서 Depends 금지"
        assert "Query(" not in src, "red_blue_view 안에서 Query 금지"


# ============================================================
# 2. red_blue_view 공개 함수 동작
# ============================================================


class TestRedBlueViewBehavior:
    def test_enrich_vulnerabilities_adds_red_keys_without_mutating_input(self):
        from api.services import red_blue_view

        vulns = [{"id": "v1", "cwe_id": "CWE-89", "severity": "HIGH"}]
        snapshot = [dict(v) for v in vulns]

        enriched = red_blue_view.enrich_vulnerabilities(vulns)

        assert vulns == snapshot, "caller 가 보낸 리스트/딕셔너리는 변경되면 안 된다"
        assert len(enriched) == 1
        assert _RED_KEYS.issubset(enriched[0].keys())
        # 원본 필드 보존
        assert enriched[0]["id"] == "v1"
        assert enriched[0]["cwe_id"] == "CWE-89"

    def test_enrich_vulnerabilities_normalizes_non_list_input(self):
        from api.services import red_blue_view

        assert red_blue_view.enrich_vulnerabilities(None) == []
        assert red_blue_view.enrich_vulnerabilities("nope") == []  # type: ignore[arg-type]
        assert red_blue_view.enrich_vulnerabilities({"id": "x"}) == []  # type: ignore[arg-type]

    def test_enrich_vulnerabilities_preserves_caller_provided_red_keys(self):
        from api.services import red_blue_view

        vulns = [
            {
                "id": "v1",
                "cwe_id": "CWE-89",
                "attack_vector": "caller-provided",
                "blue_team_strategy": "caller-provided-defense",
            }
        ]
        enriched = red_blue_view.enrich_vulnerabilities(vulns)
        assert enriched[0]["attack_vector"] == "caller-provided"
        assert enriched[0]["blue_team_strategy"] == "caller-provided-defense"

    def test_enrich_patches_adds_blue_keys_and_matches_vuln(self):
        from api.services import red_blue_view

        vulns = [{"id": "v1", "cwe_id": "CWE-89", "severity": "HIGH"}]
        patches = [
            {
                "vulnerability_id": "v1",
                "fixed_code": "bind",
                "status": "verified",
                "security_revalidation": {"passed": True, "introduced_count": 0},
            }
        ]
        patches_snapshot = [dict(p) for p in patches]

        enriched = red_blue_view.enrich_patches(patches, vulns)
        assert patches == patches_snapshot, "caller 패치 리스트는 변경되면 안 된다"
        assert len(enriched) == 1
        assert _BLUE_KEYS.issubset(enriched[0].keys())
        assert enriched[0]["defense_outcome"] == "validated_defense"
        # CWE-89 매칭 vuln 의 enriched blue_team_strategy 가 patch.defense_strategy 로
        # 전달되어야 한다 — generic fallback 이 아닌 CWE-derived 문구.
        assert "parameterized queries" in enriched[0]["defense_strategy"], (
            "CWE-89 matching vuln 의 enriched blue_team_strategy 가 "
            "patch.defense_strategy 로 전달돼야 한다 (generic fallback 금지): "
            f"{enriched[0]['defense_strategy']!r}"
        )

    def test_enrich_patches_does_not_match_empty_ids(self):
        from api.services import red_blue_view

        vulns = [{"id": "", "cwe_id": "CWE-89"}]
        patches = [{"vulnerability_id": "", "fixed_code": "x"}]
        enriched = red_blue_view.enrich_patches(patches, vulns)
        # empty id 끼리 매칭되지 않아야 한다 — 기본 defense_strategy 가 generic fallback.
        assert _BLUE_KEYS.issubset(enriched[0].keys())

    def test_enrich_patches_normalizes_non_list_input(self):
        from api.services import red_blue_view

        assert red_blue_view.enrich_patches(None) == []
        assert red_blue_view.enrich_patches("nope") == []  # type: ignore[arg-type]

    def test_build_view_summary_returns_four_top_level_keys(self):
        from api.services import red_blue_view

        result = red_blue_view.build_view_summary(
            [{"id": "v1", "cwe_id": "CWE-89", "severity": "HIGH"}],
            [{"vulnerability_id": "v1", "fixed_code": "bind", "status": "verified"}],
        )
        assert set(result.keys()) == _SUMMARY_TOP_KEYS

    def test_build_view_summary_handles_none_inputs(self):
        from api.services import red_blue_view

        result = red_blue_view.build_view_summary(None, None)
        assert set(result.keys()) == _SUMMARY_TOP_KEYS
        assert result["red_team"]["total_findings"] == 0
        assert result["attack_paths"] == []

    def test_enrich_stats_adds_summary_only_when_input_nonempty(self):
        from api.services import red_blue_view

        stats = {"total_issues": 0, "high": 0, "medium": 0, "low": 0,
                 "patches_generated": 0, "patches_verified": 0}
        stats_snapshot = dict(stats)

        # 빈 입력 — 절대 red_blue_summary 를 추가하지 않는다.
        out_empty = red_blue_view.enrich_stats(stats, [], [])
        assert stats == stats_snapshot, "원본 stats 가 변경되면 안 된다"
        assert "red_blue_summary" not in out_empty
        assert out_empty == stats

        out_none = red_blue_view.enrich_stats(stats, None, None)
        assert "red_blue_summary" not in out_none

        # 비어 있지 않은 입력 — red_blue_summary 추가.
        out = red_blue_view.enrich_stats(
            stats,
            [{"id": "v1", "cwe_id": "CWE-89", "severity": "HIGH"}],
            [{"vulnerability_id": "v1", "fixed_code": "bind", "status": "verified"}],
        )
        assert "red_blue_summary" in out
        assert set(out["red_blue_summary"].keys()) == _SUMMARY_TOP_KEYS
        # 기존 키 보존
        for k in stats:
            assert out[k] == stats[k]

    def test_enrich_analysis_result_passthrough_for_error_and_non_dict(self):
        from api.services import red_blue_view

        err = {"error": "Session not found"}
        assert red_blue_view.enrich_analysis_result(err) == err
        assert red_blue_view.enrich_analysis_result(None) is None  # type: ignore[arg-type]
        assert red_blue_view.enrich_analysis_result([1, 2]) == [1, 2]  # type: ignore[arg-type]

    def test_enrich_analysis_result_enriches_dict_with_vulnerabilities_and_patches(self):
        from api.services import red_blue_view

        payload = {
            "session_id": "s1",
            "vulnerabilities": [
                {"id": "v1", "cwe_id": "CWE-89", "severity": "HIGH"}
            ],
            "patches": [
                {"vulnerability_id": "v1", "fixed_code": "bind", "status": "verified"}
            ],
        }
        out = red_blue_view.enrich_analysis_result(payload)
        assert out["session_id"] == "s1"
        assert _RED_KEYS.issubset(out["vulnerabilities"][0].keys())
        assert _BLUE_KEYS.issubset(out["patches"][0].keys())
        assert "red_blue_summary" in out
        assert set(out["red_blue_summary"].keys()) == _SUMMARY_TOP_KEYS


# ============================================================
# 3. dashboard_queries.get_vulnerabilities — additive enrichment
# ============================================================


class TestGetVulnerabilitiesPassthrough:
    def test_top_level_shape_preserved_and_items_enriched(self, monkeypatch):
        from api.services import dashboard_queries as svc

        full = _sample_full_result()
        monkeypatch.setattr(svc.result_sources, "load_full_result", lambda: full)

        result = svc.get_vulnerabilities()
        assert set(result.keys()) == {"count", "vulnerabilities"}
        assert result["count"] == 2

        first = result["vulnerabilities"][0]
        # 기존 키/값 모두 보존
        assert first["id"] == "vuln_B608_10"
        assert first["severity"] == "HIGH"
        assert first["cwe_id"] == "CWE-89"
        # Red Team 키 추가
        for k in _RED_KEYS:
            assert k in first, f"vulnerability 가 {k} 를 가져야 함: {sorted(first.keys())}"

    def test_full_result_not_mutated(self, monkeypatch):
        from api.services import dashboard_queries as svc

        full = _sample_full_result()
        snapshot = {
            "v_keys": [sorted(v.keys()) for v in full["vulnerabilities"]],
            "p_keys": [sorted(p.keys()) for p in full["patches"]],
        }
        monkeypatch.setattr(svc.result_sources, "load_full_result", lambda: full)

        svc.get_vulnerabilities()

        new_snapshot = {
            "v_keys": [sorted(v.keys()) for v in full["vulnerabilities"]],
            "p_keys": [sorted(p.keys()) for p in full["patches"]],
        }
        assert snapshot == new_snapshot, "원본 full_result 의 키 셋이 변경되면 안 된다"

    def test_caller_provided_red_keys_not_overwritten(self, monkeypatch):
        from api.services import dashboard_queries as svc

        full = {
            "vulnerabilities": [
                {
                    "id": "v1",
                    "tool": "bandit",
                    "rule_id": "B608",
                    "severity": "HIGH",
                    "file_path": "x.py",
                    "line_number": 1,
                    "code_snippet": "...",
                    "cwe_id": "CWE-89",
                    "title": "SQLi",
                    "attack_vector": "caller-attack",
                    "blue_team_strategy": "caller-defense",
                },
            ],
        }
        monkeypatch.setattr(svc.result_sources, "load_full_result", lambda: full)

        v = svc.get_vulnerabilities()["vulnerabilities"][0]
        assert v["attack_vector"] == "caller-attack"
        assert v["blue_team_strategy"] == "caller-defense"


# ============================================================
# 4. dashboard_queries.get_patches — additive enrichment
# ============================================================


class TestGetPatchesPassthrough:
    def test_patch_meta_preserved_and_blue_keys_added(self, monkeypatch):
        from api.services import dashboard_queries as svc

        full = _sample_full_result()
        monkeypatch.setattr(svc.result_sources, "load_full_result", lambda: full)

        result = svc.get_patches()
        assert set(result.keys()) == {"count", "patches"}
        assert result["count"] == 1

        p = result["patches"][0]
        # 기존 enrichment 키 보존
        assert p["file_path"] == "app.py"
        assert p["line_number"] == 10
        assert p["rule_id"] == "B608"
        assert p["severity"] == "HIGH"
        assert p["title"] == "SQL Injection"
        assert p["original_code"].startswith("def get():")
        # Blue Team 키 추가
        for k in _BLUE_KEYS:
            assert k in p, f"patch 가 {k} 를 가져야 함: {sorted(p.keys())}"
        # 매칭된 vuln 의 컨텍스트로 outcome 이 결정됐다.
        assert p["defense_outcome"] == "validated_defense"
        assert p["residual_risk"] == "low"
        # CWE-89 매칭 vuln 의 enriched blue_team_strategy 가 그대로 patch
        # defense_strategy 로 전달돼야 한다 (route/service 통합 경로 확인).
        assert "parameterized queries" in p["defense_strategy"], (
            "route/service 경로에서도 CWE-89 enriched blue_team_strategy 가 "
            "patch.defense_strategy 로 전달돼야 한다: "
            f"{p['defense_strategy']!r}"
        )


# ============================================================
# 5. dashboard_queries.get_stats — JSON fallback adds summary; empty stays exact
# ============================================================


class TestGetStatsPassthrough:
    def test_json_fallback_adds_red_blue_summary(self, monkeypatch):
        from api.services import dashboard_queries as svc

        monkeypatch.setattr(
            svc.db_service, "get_stats",
            lambda: {
                "total_issues": 0, "high": 0, "medium": 0, "low": 0,
                "patches_generated": 0, "patches_verified": 0,
            },
        )
        monkeypatch.setattr(
            svc.result_sources, "load_full_result", lambda: _sample_full_result(),
        )

        result = svc.get_stats()
        # 기존 키/값 보존
        assert result["total_issues"] == 2
        assert result["high"] == 1
        assert result["medium"] == 1
        assert result["session_id"] == "sess-w5d"
        # additive 키 추가
        assert "red_blue_summary" in result
        assert set(result["red_blue_summary"].keys()) == _SUMMARY_TOP_KEYS

    def test_empty_fallback_preserves_exact_six_keys(self, monkeypatch):
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
            lambda: {"results": [], "metrics": {"_totals": {}}},
        )

        result = svc.get_stats()
        assert set(result.keys()) == {
            "total_issues", "high", "medium", "low",
            "patches_generated", "patches_verified",
        }, "빈 폴백은 6개 키만 가져야 한다 (red_blue_summary 추가 금지)"

    def test_db_first_path_unchanged_when_no_raw_lists(self, monkeypatch):
        from api.services import dashboard_queries as svc

        db_payload = {
            "total_issues": 5, "high": 2, "medium": 2, "low": 1,
            "patches_generated": 3, "patches_verified": 2,
            "session_id": "sess-db", "total_sessions": 7,
        }
        monkeypatch.setattr(svc.db_service, "get_stats", lambda: db_payload)
        result = svc.get_stats()
        assert result == db_payload, (
            "DB 집계 경로(raw vulnerabilities/patches 없음)는 가짜 summary 를 만들면 안 된다"
        )


# ============================================================
# 6. dashboard_queries.get_session_detail — passthrough
# ============================================================


class TestGetSessionDetailPassthrough:
    def test_missing_session_error_preserved(self, monkeypatch):
        from api.services import dashboard_queries as svc

        monkeypatch.setattr(
            svc.db_service, "get_analysis_by_session", lambda sid: None,
        )
        assert svc.get_session_detail("missing") == {"error": "Session not found"}

    def test_session_detail_enriched_when_vulns_and_patches_present(self, monkeypatch):
        from api.services import dashboard_queries as svc

        payload = {
            "session_id": "s1",
            "vulnerabilities": [
                {"id": "v1", "cwe_id": "CWE-89", "severity": "HIGH"}
            ],
            "patches": [
                {"vulnerability_id": "v1", "fixed_code": "bind", "status": "verified"}
            ],
        }
        monkeypatch.setattr(
            svc.db_service, "get_analysis_by_session", lambda sid: payload,
        )

        result = svc.get_session_detail("s1")
        assert result["session_id"] == "s1"
        assert _RED_KEYS.issubset(result["vulnerabilities"][0].keys())
        assert _BLUE_KEYS.issubset(result["patches"][0].keys())
        assert "red_blue_summary" in result
        assert set(result["red_blue_summary"].keys()) == _SUMMARY_TOP_KEYS


# ============================================================
# 7. HTTP route passthrough — DTO 의 _Permissive(extra="allow") 확인
# ============================================================


def _patch_full(monkeypatch):
    monkeypatch.setattr(
        result_sources, "load_full_result", lambda: _sample_full_result(),
    )


class TestHttpRoutePassthrough:
    def test_get_vulnerabilities_route_carries_red_keys(self, monkeypatch):
        _patch_full(monkeypatch)
        client = TestClient(app)
        r = client.get("/api/vulnerabilities", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["count"] == 2
        item = data["vulnerabilities"][0]
        for k in _RED_KEYS:
            assert k in item, (
                f"HTTP 응답 vulnerabilities[0] 에 {k} 가 누락됨 — DTO 가 떨어뜨림: "
                f"{sorted(item.keys())}"
            )

    def test_get_patches_route_carries_blue_keys(self, monkeypatch):
        _patch_full(monkeypatch)
        client = TestClient(app)
        r = client.get("/api/patches", headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["count"] == 1
        item = data["patches"][0]
        for k in _BLUE_KEYS:
            assert k in item, (
                f"HTTP 응답 patches[0] 에 {k} 가 누락됨 — DTO 가 떨어뜨림: "
                f"{sorted(item.keys())}"
            )

    def test_auth_still_enforced(self):
        client = TestClient(app)
        r = client.get("/api/vulnerabilities")
        assert r.status_code in (401, 403)


# ============================================================
# 8. 라우터 본문은 여전히 얇아야 한다
# ============================================================


class TestRouterRemainsThin:
    def test_router_does_not_import_red_blue_view(self):
        import api.routers.dashboard as mod

        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                # 라우터는 red_blue_view 를 직접 import 하지 않는다.
                # enrichment 는 dashboard_queries 서비스 안에서 일어난다.
                if node.module == "api.services.red_blue_view":
                    raise AssertionError(
                        "라우터에서 red_blue_view 직접 import 금지 — "
                        "dashboard_queries 서비스에 위임해야 한다"
                    )
