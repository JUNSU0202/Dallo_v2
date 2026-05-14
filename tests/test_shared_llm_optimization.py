"""Wave 5-E shared/llm_optimization.py 단위 테스트.

본 테스트는 ``shared/llm_optimization.py`` 의 LLM 입력 최적화 헬퍼의
행동 계약을 검증한다. 본 모듈은 순수 모듈이며, 어떠한 실제 외부 도구도
호출하지 않는다 — FastAPI / DB / disk / network / clock / subprocess /
env / LLM / agent / validator / dashboard 와 접점이 없다.

검증 항목:
- 모듈 임포트 및 기본 config 값
- summary 상위 / scope 하위 키 셋
- CWE alias / rule / CVE 텍스트 필터링
- 스코프 미지정 시 전부 선택
- ``enabled=False`` 시 원본 순서 보존 (필터/정렬/cap 없음, deepcopy/trim 만)
- risk / severity / CVSS 결정적 정렬 + 안전한 fallback
- ``max_targets`` cap 및 ``<= 0`` 무한대 처리
- ``function_code`` / ``code_snippet`` / ``file_imports`` 의 trim
- ``max_context_chars <= 0`` 일 때 trim 미적용
- 입력 비파괴 (deep copy)
- 실제 ``shared.schemas.VulnerabilityReport`` 와의 호환성
- AST 순수성 가드 (금지된 import / call 0 건)
- gateway / claude-sonnet / LLM_PRIMARY_PROVIDER 토큰 부재
"""

from __future__ import annotations

import ast
import pathlib
from dataclasses import dataclass, field

import pytest

from shared.llm_optimization import (
    LLMOptimizationConfig,
    SCOPE_ALIASES,
    optimize_llm_targets,
    scoped_copy,
    trim_vulnerability_context,
)
from shared.schemas import VulnerabilityReport


# ---------------------------------------------------------------------------
# 헬퍼: 테스트용 가벼운 vuln object. dict 이 아니라 attribute-access object 다.
# ---------------------------------------------------------------------------


@dataclass
class _FakeVuln:
    id: str = ""
    tool: str = "bandit"
    rule_id: str = ""
    severity: str = "LOW"
    confidence: str = "LOW"
    title: str = ""
    description: str = ""
    file_path: str = ""
    line_number: int = 0
    code_snippet: str = ""
    function_code: str = ""
    file_imports: str = ""
    cwe_id: str = ""
    language: str = "python"
    more_info: str = ""
    risk_level: str = ""
    cvss_score: float = 0.0
    duplicate_group_id: str = ""
    created_at: str = ""
    extra_payload: dict = field(default_factory=dict)


def _v(**kwargs) -> _FakeVuln:
    return _FakeVuln(**kwargs)


# ---------------------------------------------------------------------------
# 1. 모듈 임포트 및 기본 config
# ---------------------------------------------------------------------------


def test_default_config_values():
    cfg = LLMOptimizationConfig()
    assert cfg.enabled is True
    assert cfg.cve_scope == []
    assert cfg.cwe_scope == []
    assert cfg.rule_scope == []
    assert cfg.max_targets == 10
    assert cfg.max_context_chars == 2400
    assert cfg.batch_enabled is True
    assert cfg.batch_size == 5


def test_scope_aliases_known_mappings():
    assert SCOPE_ALIASES["SQLI"] == "CWE-89"
    assert SCOPE_ALIASES["CMDI"] == "CWE-78"
    assert SCOPE_ALIASES["XSS"] == "CWE-79"
    assert SCOPE_ALIASES["AUTH_BYPASS"] == "CWE-288"
    assert SCOPE_ALIASES["PATH_TRAVERSAL"] == "CWE-22"
    assert SCOPE_ALIASES["HARDCODED_SECRET"] == "CWE-798"


def test_optimize_with_none_config_uses_defaults():
    vulns = [_v(id="v1", cwe_id="CWE-89", severity="HIGH")]
    targets, summary = optimize_llm_targets(vulns, None)
    assert len(targets) == 1
    assert summary["enabled"] is True
    assert summary["max_targets"] == 10
    assert summary["max_context_chars"] == 2400
    assert summary["batch_enabled"] is True
    assert summary["batch_size"] == 5


# ---------------------------------------------------------------------------
# 2. summary 상위 / scope 하위 키 셋
# ---------------------------------------------------------------------------


_EXPECTED_SUMMARY_KEYS = {
    "enabled",
    "input_count",
    "selected_count",
    "cap_applied",
    "max_targets",
    "max_context_chars",
    "batch_enabled",
    "batch_size",
    "scope",
}

_EXPECTED_SCOPE_KEYS = {"cve", "cwe", "rule", "aliases_used"}


def test_summary_top_level_exact_key_set():
    _, summary = optimize_llm_targets([])
    assert set(summary.keys()) == _EXPECTED_SUMMARY_KEYS


def test_summary_scope_exact_key_set():
    _, summary = optimize_llm_targets([])
    assert set(summary["scope"].keys()) == _EXPECTED_SCOPE_KEYS
    # scope 의 각 값은 list 여야 한다 (JSON 호환).
    for key in _EXPECTED_SCOPE_KEYS:
        assert isinstance(summary["scope"][key], list)


def test_summary_is_json_compatible_types():
    cfg = LLMOptimizationConfig(cwe_scope=["SQLI"], rule_scope=["B608"], cve_scope=["CVE-2024-0001"])
    _, summary = optimize_llm_targets([_v(id="v1", cwe_id="CWE-89")], cfg)
    # int / bool / list / dict / str 만 사용. 데이터클래스/Enum 등 비-JSON 타입 금지.
    allowed = (int, bool, str, list, dict, float, type(None))
    for k, v in summary.items():
        assert isinstance(v, allowed), f"summary[{k!r}] = {v!r}"


# ---------------------------------------------------------------------------
# 3. CWE alias 필터링
# ---------------------------------------------------------------------------


def test_cwe_alias_sqli_selects_only_cwe_89():
    vulns = [
        _v(id="v1", cwe_id="CWE-89", severity="HIGH"),
        _v(id="v2", cwe_id="CWE-78", severity="HIGH"),
        _v(id="v3", cwe_id="CWE-79", severity="HIGH"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=["SQLI"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    selected_ids = {t.id for t in targets}
    assert selected_ids == {"v1"}
    assert summary["selected_count"] == 1
    assert "CWE-89" in summary["scope"]["cwe"]
    assert "SQLI" in summary["scope"]["aliases_used"]


def test_cwe_alias_cmdi_case_insensitive():
    vulns = [
        _v(id="v1", cwe_id="CWE-78"),
        _v(id="v2", cwe_id="CWE-89"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=["cmdi"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]
    assert "CWE-78" in summary["scope"]["cwe"]


def test_cwe_alias_auth_bypass_and_path_traversal():
    vulns = [
        _v(id="v1", cwe_id="CWE-288"),
        _v(id="v2", cwe_id="CWE-22"),
        _v(id="v3", cwe_id="CWE-89"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=["auth_bypass", "PATH_TRAVERSAL"])
    targets, _ = optimize_llm_targets(vulns, cfg)
    assert {t.id for t in targets} == {"v1", "v2"}


def test_cwe_direct_token_match_without_alias():
    vulns = [
        _v(id="v1", cwe_id="CWE-89"),
        _v(id="v2", cwe_id="CWE-78"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=["CWE-89"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]
    # 직접 토큰 매칭 시 aliases_used 에는 추가되지 않는다.
    assert "CWE-89" not in summary["scope"]["aliases_used"]
    assert summary["scope"]["aliases_used"] == []


def test_cwe_hardcoded_secret_alias():
    vulns = [
        _v(id="v1", cwe_id="CWE-798"),
        _v(id="v2", cwe_id="CWE-89"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=["HARDCODED_SECRET"])
    targets, _ = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]


# ---------------------------------------------------------------------------
# 3-bis. Alias variant 확장: SQL-INJECTION / SQL_INJECTION /
#        COMMAND-INJECTION / COMMAND_INJECTION / AUTHENTICATION-BYPASS /
#        AUTHENTICATION_BYPASS — Gusle01 의 원본 alias 의도.
# ---------------------------------------------------------------------------


def test_cwe_alias_sql_injection_hyphen_form_maps_to_cwe_89():
    vulns = [
        _v(id="v1", cwe_id="CWE-89"),
        _v(id="v2", cwe_id="CWE-78"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=["SQL-INJECTION"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]
    assert "CWE-89" in summary["scope"]["cwe"]


def test_cwe_alias_sql_injection_underscore_form_maps_to_cwe_89():
    vulns = [
        _v(id="v1", cwe_id="CWE-89"),
        _v(id="v2", cwe_id="CWE-78"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=["SQL_INJECTION"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]
    assert "CWE-89" in summary["scope"]["cwe"]


def test_cwe_alias_command_injection_hyphen_form_maps_to_cwe_78():
    vulns = [
        _v(id="v1", cwe_id="CWE-78"),
        _v(id="v2", cwe_id="CWE-89"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=["COMMAND-INJECTION"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]
    assert "CWE-78" in summary["scope"]["cwe"]


def test_cwe_alias_command_injection_underscore_form_maps_to_cwe_78():
    vulns = [
        _v(id="v1", cwe_id="CWE-78"),
        _v(id="v2", cwe_id="CWE-89"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=["COMMAND_INJECTION"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]
    assert "CWE-78" in summary["scope"]["cwe"]


def test_cwe_alias_authentication_bypass_hyphen_form_maps_to_cwe_288():
    vulns = [
        _v(id="v1", cwe_id="CWE-288"),
        _v(id="v2", cwe_id="CWE-89"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=["AUTHENTICATION-BYPASS"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]
    assert "CWE-288" in summary["scope"]["cwe"]


def test_cwe_alias_authentication_bypass_underscore_form_maps_to_cwe_288():
    vulns = [
        _v(id="v1", cwe_id="CWE-288"),
        _v(id="v2", cwe_id="CWE-89"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=["AUTHENTICATION_BYPASS"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]
    assert "CWE-288" in summary["scope"]["cwe"]


def test_existing_short_aliases_still_work_after_extension():
    # AUTH_BYPASS / PATH_TRAVERSAL / HARDCODED_SECRET 그대로 유지.
    vulns = [
        _v(id="v_auth", cwe_id="CWE-288"),
        _v(id="v_path", cwe_id="CWE-22"),
        _v(id="v_secret", cwe_id="CWE-798"),
        _v(id="v_other", cwe_id="CWE-89"),
    ]
    cfg = LLMOptimizationConfig(
        cwe_scope=["AUTH_BYPASS", "PATH_TRAVERSAL", "HARDCODED_SECRET"]
    )
    targets, _ = optimize_llm_targets(vulns, cfg)
    assert {t.id for t in targets} == {"v_auth", "v_path", "v_secret"}


# ---------------------------------------------------------------------------
# 3-ter. 안전 가드: 알 수 없는 의미 있는 scope 토큰은 전체로 broaden 되지 않는다.
# ---------------------------------------------------------------------------


def test_unknown_cwe_alias_narrows_to_zero_not_all():
    vulns = [
        _v(id="v1", cwe_id="CWE-89", severity="HIGH"),
        _v(id="v2", cwe_id="CWE-78", severity="HIGH"),
        _v(id="v3", cwe_id="CWE-79", severity="HIGH"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=["NOT_A_REAL_CWE_ALIAS"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert targets == []
    assert summary["selected_count"] == 0
    assert summary["input_count"] == 3
    assert summary["scope"]["cwe"] == []


def test_unknown_cwe_alias_mixed_with_known_keeps_known():
    # 의미 있는 unknown + 의미 있는 known 이 함께 들어오면, known 토큰은 정상 작동.
    vulns = [
        _v(id="v1", cwe_id="CWE-89"),
        _v(id="v2", cwe_id="CWE-78"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=["NOT_A_REAL_CWE_ALIAS", "SQLI"])
    targets, _ = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]


def test_blank_only_cwe_scope_behaves_as_no_scope_and_selects_all():
    # None / "" / "   " 만 들어있는 경우는 "scope 미설정" 으로 간주, 전부 선택.
    vulns = [
        _v(id="v1", cwe_id="CWE-89"),
        _v(id="v2", cwe_id="CWE-78"),
        _v(id="v3", cwe_id="CWE-79"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=[None, "", "   "])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert {t.id for t in targets} == {"v1", "v2", "v3"}
    assert summary["selected_count"] == 3
    assert summary["scope"]["cwe"] == []


def test_unknown_rule_scope_does_not_broaden_to_all():
    vulns = [
        _v(id="v1", rule_id="B608", cwe_id="CWE-89"),
        _v(id="v2", rule_id="B602", cwe_id="CWE-78"),
    ]
    cfg = LLMOptimizationConfig(rule_scope=["NO_SUCH_RULE"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert targets == []
    assert summary["selected_count"] == 0
    assert summary["input_count"] == 2


def test_unknown_cve_scope_does_not_broaden_to_all():
    vulns = [
        _v(id="v1", description="CVE-2024-12345"),
        _v(id="v2", description="unrelated"),
    ]
    cfg = LLMOptimizationConfig(cve_scope=["CVE-9999-9999"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert targets == []
    assert summary["selected_count"] == 0
    assert summary["input_count"] == 2


def test_blank_only_rule_scope_behaves_as_no_scope_and_selects_all():
    vulns = [
        _v(id="v1", rule_id="B608"),
        _v(id="v2", rule_id="B602"),
    ]
    cfg = LLMOptimizationConfig(rule_scope=[None, "", "   "])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert {t.id for t in targets} == {"v1", "v2"}
    assert summary["selected_count"] == 2


def test_blank_only_cve_scope_behaves_as_no_scope_and_selects_all():
    vulns = [
        _v(id="v1"),
        _v(id="v2"),
    ]
    cfg = LLMOptimizationConfig(cve_scope=[None, "", "   "])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert {t.id for t in targets} == {"v1", "v2"}
    assert summary["selected_count"] == 2


def test_new_aliases_registered_in_scope_aliases_table():
    # 신규 alias 토큰들도 공식 사전에 노출되어 운영자가 확인 가능해야 한다.
    assert SCOPE_ALIASES["SQL_INJECTION"] == "CWE-89"
    assert SCOPE_ALIASES["COMMAND_INJECTION"] == "CWE-78"
    assert SCOPE_ALIASES["AUTHENTICATION_BYPASS"] == "CWE-288"
    # 기존 alias 도 유지.
    assert SCOPE_ALIASES["AUTH_BYPASS"] == "CWE-288"
    assert SCOPE_ALIASES["PATH_TRAVERSAL"] == "CWE-22"
    assert SCOPE_ALIASES["HARDCODED_SECRET"] == "CWE-798"


# ---------------------------------------------------------------------------
# 3-quater. Cross-category 안전 가드.
# 한 카테고리의 알 수 없는 토큰 때문에 다른 카테고리의 유효한 scope 가
# 무효화되어서는 안 된다. 의미 있는 scope 중 하나라도 해석되면 그 해석된
# scope 로 정상 필터링, 모든 의미 있는 카테고리가 해석 불가일 때만 0 으로
# 좁힌다.
# ---------------------------------------------------------------------------


def test_unknown_cwe_with_valid_rule_still_filters_by_rule():
    vulns = [
        _v(id="v1", rule_id="B608", cwe_id="CWE-89"),
        _v(id="v2", rule_id="B602", cwe_id="CWE-78"),
    ]
    cfg = LLMOptimizationConfig(
        cwe_scope=["NOT_A_REAL_CWE"], rule_scope=["B608"]
    )
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]
    assert summary["selected_count"] == 1
    assert summary["input_count"] == 2
    assert summary["scope"]["cwe"] == []
    assert "B608" in summary["scope"]["rule"]


def test_unknown_cwe_with_valid_cve_still_filters_by_cve():
    vulns = [
        _v(id="v1", description="See CVE-2024-12345 for details"),
        _v(id="v2", description="unrelated"),
    ]
    cfg = LLMOptimizationConfig(
        cwe_scope=["NOT_A_REAL_CWE"], cve_scope=["CVE-2024-12345"]
    )
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]
    assert summary["selected_count"] == 1
    assert summary["scope"]["cwe"] == []
    assert "CVE-2024-12345" in summary["scope"]["cve"]


def test_unknown_rule_with_valid_cwe_still_filters_by_cwe():
    # rule_scope=["NOT_REAL"] 은 rule_resolved 에 그대로 보존되지만 어떤 vuln 도
    # rule_id="NOT_REAL" 을 갖지 않으므로 OR 필터링에서 cwe 만 의미 있게 작동.
    vulns = [
        _v(id="v1", rule_id="B608", cwe_id="CWE-89"),
        _v(id="v2", rule_id="B602", cwe_id="CWE-78"),
    ]
    cfg = LLMOptimizationConfig(
        rule_scope=["NOT_REAL"], cwe_scope=["SQLI"]
    )
    targets, _ = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]


def test_unknown_cve_with_valid_cwe_still_filters_by_cwe():
    vulns = [
        _v(id="v1", cwe_id="CWE-89", description="no cve here"),
        _v(id="v2", cwe_id="CWE-78", description="no cve here either"),
    ]
    cfg = LLMOptimizationConfig(
        cve_scope=["CVE-9999-9999"], cwe_scope=["SQLI"]
    )
    targets, _ = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]


def test_multiple_unknown_categories_with_one_valid_still_uses_valid():
    # cwe 해석 실패 + cve 어떤 vuln 에도 매칭 안 됨 + rule 만 유효.
    vulns = [
        _v(id="v1", cwe_id="CWE-89", rule_id="B608"),
        _v(id="v2", cwe_id="CWE-78", rule_id="B602"),
    ]
    cfg = LLMOptimizationConfig(
        cwe_scope=["NOT_A_REAL_CWE"],
        cve_scope=["CVE-9999-9999"],
        rule_scope=["B608"],
    )
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]
    assert summary["selected_count"] == 1


def test_all_meaningful_categories_unresolved_still_narrows_to_zero():
    # cwe scope 토큰들이 모두 해석 불가, 다른 카테고리는 비어있음 → 0.
    vulns = [
        _v(id="v1", cwe_id="CWE-89"),
        _v(id="v2", cwe_id="CWE-78"),
    ]
    cfg = LLMOptimizationConfig(cwe_scope=["NOT_A_REAL_CWE", "ALSO_FAKE"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert targets == []
    assert summary["selected_count"] == 0
    assert summary["input_count"] == 2
    assert summary["scope"]["cwe"] == []


# ---------------------------------------------------------------------------
# 4. rule scope 필터링
# ---------------------------------------------------------------------------


def test_rule_scope_matches_normalized_rule_id():
    vulns = [
        _v(id="v1", rule_id="B608", cwe_id="CWE-89"),
        _v(id="v2", rule_id="B602", cwe_id="CWE-78"),
        _v(id="v3", rule_id="B103", cwe_id="CWE-732"),
    ]
    cfg = LLMOptimizationConfig(rule_scope=["b608", "B602"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert {t.id for t in targets} == {"v1", "v2"}
    assert set(summary["scope"]["rule"]) == {"B608", "B602"}


# ---------------------------------------------------------------------------
# 5. CVE 텍스트 필터링
# ---------------------------------------------------------------------------


def test_cve_text_matches_in_description():
    vulns = [
        _v(id="v1", description="See CVE-2024-12345 for details", cwe_id="CWE-89"),
        _v(id="v2", description="unrelated", cwe_id="CWE-89"),
    ]
    cfg = LLMOptimizationConfig(cve_scope=["CVE-2024-12345"])
    targets, _ = optimize_llm_targets(vulns, cfg)
    assert [t.id for t in targets] == ["v1"]


def test_cve_text_matches_in_multiple_fields():
    vulns = [
        _v(id="v1", title="CVE-2023-1111 sql"),
        _v(id="v2", more_info="https://nvd.nist.gov/CVE-2023-1111"),
        _v(id="v3", description="no match here"),
    ]
    cfg = LLMOptimizationConfig(cve_scope=["CVE-2023-1111"])
    targets, _ = optimize_llm_targets(vulns, cfg)
    assert {t.id for t in targets} == {"v1", "v2"}


# ---------------------------------------------------------------------------
# 6. 스코프 미지정 시 전부 선택 (cap 적용 가능)
# ---------------------------------------------------------------------------


def test_no_scope_selects_all():
    vulns = [
        _v(id="v1", cwe_id="CWE-89"),
        _v(id="v2", cwe_id="CWE-78"),
        _v(id="v3", cwe_id="CWE-22"),
    ]
    cfg = LLMOptimizationConfig()  # 모든 scope 비어있음
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert len(targets) == 3
    assert summary["selected_count"] == 3
    assert summary["scope"]["cwe"] == []
    assert summary["scope"]["rule"] == []
    assert summary["scope"]["cve"] == []


# ---------------------------------------------------------------------------
# 7. enabled=False: 원본 순서 보존, deepcopy/trim 만
# ---------------------------------------------------------------------------


def test_disabled_preserves_original_order_and_count():
    vulns = [
        _v(id="v3", cwe_id="CWE-79", severity="LOW", risk_level="low"),
        _v(id="v1", cwe_id="CWE-89", severity="HIGH", risk_level="critical"),
        _v(id="v2", cwe_id="CWE-78", severity="HIGH", risk_level="high"),
    ]
    cfg = LLMOptimizationConfig(enabled=False, max_targets=1, cwe_scope=["SQLI"])
    targets, summary = optimize_llm_targets(vulns, cfg)
    # filter/sort/cap 무시. 원본 순서 그대로 3 개 모두 반환.
    assert [t.id for t in targets] == ["v3", "v1", "v2"]
    assert summary["enabled"] is False
    assert summary["selected_count"] == 3
    assert summary["input_count"] == 3
    assert summary["cap_applied"] is False


def test_disabled_still_deepcopies_targets():
    payload = {"k": ["a", "b"]}
    vuln = _v(id="v1")
    vuln.extra_payload = payload
    cfg = LLMOptimizationConfig(enabled=False)
    targets, _ = optimize_llm_targets([vuln], cfg)
    targets[0].extra_payload["k"].append("c")
    assert payload["k"] == ["a", "b"]


def test_disabled_still_trims_long_context():
    big = "A" * 5000
    vuln = _v(id="v1", function_code=big)
    cfg = LLMOptimizationConfig(enabled=False, max_context_chars=200)
    targets, _ = optimize_llm_targets([vuln], cfg)
    assert len(targets[0].function_code) < 5000
    assert len(targets[0].function_code) <= 200 + 80  # 마커 오버헤드 여유


# ---------------------------------------------------------------------------
# 8. risk / severity / CVSS 결정적 정렬
# ---------------------------------------------------------------------------


def test_priority_sort_risk_level_first():
    vulns = [
        _v(id="v_low", risk_level="low", severity="HIGH", cvss_score=9.9, cwe_id="CWE-89"),
        _v(id="v_critical", risk_level="critical", severity="LOW", cvss_score=1.0, cwe_id="CWE-89"),
        _v(id="v_high", risk_level="high", severity="MEDIUM", cvss_score=5.0, cwe_id="CWE-89"),
        _v(id="v_medium", risk_level="medium", severity="HIGH", cvss_score=7.0, cwe_id="CWE-89"),
    ]
    targets, _ = optimize_llm_targets(vulns)
    assert [t.id for t in targets] == ["v_critical", "v_high", "v_medium", "v_low"]


def test_priority_sort_severity_breaks_tie_after_risk():
    vulns = [
        _v(id="va", risk_level="high", severity="LOW", cvss_score=5.0),
        _v(id="vb", risk_level="high", severity="HIGH", cvss_score=5.0),
        _v(id="vc", risk_level="high", severity="MEDIUM", cvss_score=5.0),
    ]
    targets, _ = optimize_llm_targets(vulns)
    assert [t.id for t in targets] == ["vb", "vc", "va"]


def test_priority_sort_cvss_descending_after_severity():
    vulns = [
        _v(id="lo", risk_level="high", severity="HIGH", cvss_score=4.0),
        _v(id="hi", risk_level="high", severity="HIGH", cvss_score=9.5),
        _v(id="md", risk_level="high", severity="HIGH", cvss_score=7.0),
    ]
    targets, _ = optimize_llm_targets(vulns)
    assert [t.id for t in targets] == ["hi", "md", "lo"]


def test_priority_sort_file_and_line_deterministic():
    vulns = [
        _v(id="z", risk_level="high", severity="HIGH", cvss_score=7.0,
           file_path="z.py", line_number=1),
        _v(id="a2", risk_level="high", severity="HIGH", cvss_score=7.0,
           file_path="a.py", line_number=20),
        _v(id="a1", risk_level="high", severity="HIGH", cvss_score=7.0,
           file_path="a.py", line_number=5),
    ]
    targets, _ = optimize_llm_targets(vulns)
    assert [t.id for t in targets] == ["a1", "a2", "z"]


def test_priority_sort_invalid_cvss_does_not_crash():
    @dataclass
    class _Weird:
        id: str = ""
        rule_id: str = ""
        severity: str = "HIGH"
        confidence: str = "HIGH"
        title: str = ""
        description: str = ""
        file_path: str = ""
        line_number: int = 0
        code_snippet: str = ""
        function_code: str = ""
        file_imports: str = ""
        cwe_id: str = ""
        risk_level: str = ""
        cvss_score: object = None  # 의도적으로 잘못된 타입
        more_info: str = ""

    vulns = [
        _Weird(id="bad", cvss_score="not-a-number"),
        _Weird(id="none", cvss_score=None),
        _Weird(id="ok", cvss_score=8.0),
    ]
    targets, _ = optimize_llm_targets(vulns)
    # ok 가 가장 높은 cvss 이므로 첫 번째.
    assert targets[0].id == "ok"


def test_priority_sort_missing_attributes_safe():
    # risk_level / severity / cvss / file_path / line_number 누락 객체.
    @dataclass
    class _Sparse:
        id: str = "sp"
        rule_id: str = ""
        title: str = ""
        description: str = ""
        cwe_id: str = ""
        more_info: str = ""
        code_snippet: str = ""
        function_code: str = ""
        file_imports: str = ""

    targets, _ = optimize_llm_targets([_Sparse()])
    assert len(targets) == 1


# ---------------------------------------------------------------------------
# 9. max_targets cap
# ---------------------------------------------------------------------------


def test_max_targets_caps_selection():
    vulns = [
        _v(id=f"v{i}", risk_level="high", severity="HIGH", cvss_score=9.0 - i * 0.1,
           file_path=f"f{i}.py")
        for i in range(20)
    ]
    cfg = LLMOptimizationConfig(max_targets=3)
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert len(targets) == 3
    assert summary["selected_count"] == 3
    assert summary["input_count"] == 20
    assert summary["cap_applied"] is True


def test_max_targets_zero_means_no_cap():
    vulns = [_v(id=f"v{i}", cwe_id="CWE-89") for i in range(50)]
    cfg = LLMOptimizationConfig(max_targets=0)
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert len(targets) == 50
    assert summary["cap_applied"] is False


def test_max_targets_negative_means_no_cap():
    vulns = [_v(id=f"v{i}", cwe_id="CWE-89") for i in range(15)]
    cfg = LLMOptimizationConfig(max_targets=-1)
    targets, summary = optimize_llm_targets(vulns, cfg)
    assert len(targets) == 15
    assert summary["cap_applied"] is False


# ---------------------------------------------------------------------------
# 10. context trim
# ---------------------------------------------------------------------------


def test_trim_function_code_when_exceeds_max():
    big = "F" * 8000
    vuln = _v(id="v1", function_code=big)
    out = trim_vulnerability_context(vuln, 300)
    assert len(out.function_code) <= 300 + 80
    assert len(out.function_code) < 8000


def test_trim_code_snippet_when_exceeds_max():
    big = "S" * 4000
    vuln = _v(id="v1", code_snippet=big)
    out = trim_vulnerability_context(vuln, 100)
    assert len(out.code_snippet) <= 100 + 80
    assert len(out.code_snippet) < 4000


def test_trim_file_imports_when_exceeds_max():
    big = "import x\n" * 1000
    vuln = _v(id="v1", file_imports=big)
    out = trim_vulnerability_context(vuln, 200)
    assert len(out.file_imports) <= 200 + 80
    assert len(out.file_imports) < len(big)


def test_trim_preserves_short_strings_unchanged():
    short_fn = "def f(): return 1"
    vuln = _v(id="v1", function_code=short_fn, code_snippet="x = 1")
    out = trim_vulnerability_context(vuln, 1000)
    assert out.function_code == short_fn
    assert out.code_snippet == "x = 1"


def test_no_trim_when_max_context_chars_zero():
    big = "A" * 5000
    vuln = _v(id="v1", function_code=big, code_snippet=big, file_imports=big)
    out = trim_vulnerability_context(vuln, 0)
    assert out.function_code == big
    assert out.code_snippet == big
    assert out.file_imports == big


def test_no_trim_when_max_context_chars_negative():
    big = "A" * 3000
    vuln = _v(id="v1", function_code=big)
    out = trim_vulnerability_context(vuln, -10)
    assert out.function_code == big


def test_scoped_copy_alias_of_trim():
    big = "B" * 2000
    vuln = _v(id="v1", function_code=big)
    out = scoped_copy(vuln, 200)
    assert len(out.function_code) <= 200 + 80


def test_optimize_applies_context_trim_to_selected_targets():
    big = "C" * 6000
    vulns = [_v(id="v1", cwe_id="CWE-89", function_code=big, code_snippet=big)]
    cfg = LLMOptimizationConfig(max_context_chars=150)
    targets, _ = optimize_llm_targets(vulns, cfg)
    assert len(targets[0].function_code) <= 150 + 80
    assert len(targets[0].code_snippet) <= 150 + 80


# ---------------------------------------------------------------------------
# 11. 입력 비파괴 (deep copy)
# ---------------------------------------------------------------------------


def test_optimize_does_not_mutate_input_objects():
    big = "Z" * 3000
    original = _v(id="v1", cwe_id="CWE-89", severity="HIGH", function_code=big)
    cfg = LLMOptimizationConfig(max_context_chars=200)
    targets, _ = optimize_llm_targets([original], cfg)
    # 원본 function_code 는 그대로.
    assert original.function_code == big
    assert original.severity == "HIGH"
    # 결과는 deepcopy 이므로 별개 객체.
    assert targets[0] is not original


def test_optimize_does_not_mutate_input_list():
    vulns = [_v(id="v1"), _v(id="v2"), _v(id="v3")]
    snapshot_ids = [v.id for v in vulns]
    optimize_llm_targets(vulns, LLMOptimizationConfig(max_targets=1))
    assert [v.id for v in vulns] == snapshot_ids


def test_trim_does_not_mutate_input():
    big = "Q" * 4000
    vuln = _v(id="v1", function_code=big)
    trim_vulnerability_context(vuln, 100)
    assert vuln.function_code == big


# ---------------------------------------------------------------------------
# 12. 실제 shared.schemas.VulnerabilityReport 호환성
# ---------------------------------------------------------------------------


def test_works_with_real_vulnerability_report():
    vr = VulnerabilityReport(
        id="real_v1",
        tool="bandit",
        rule_id="B608",
        severity="HIGH",
        confidence="HIGH",
        title="SQL injection",
        description="Possible SQL injection",
        file_path="api/queries.py",
        line_number=42,
        code_snippet="cursor.execute(f'SELECT * FROM t WHERE id = {uid}')",
        function_code="def q(uid):\n    cursor.execute(f'SELECT * FROM t WHERE id = {uid}')",
        cwe_id="CWE-89",
        risk_level="critical",
        cvss_score=9.8,
    )
    cfg = LLMOptimizationConfig(cwe_scope=["SQLI"], max_targets=5)
    targets, summary = optimize_llm_targets([vr], cfg)
    assert len(targets) == 1
    assert isinstance(targets[0], VulnerabilityReport)
    assert targets[0].id == "real_v1"
    assert summary["selected_count"] == 1
    # 원본 비파괴.
    assert vr.cwe_id == "CWE-89"


def test_real_vulnerability_report_trim_applied():
    big = "X" * 5000
    vr = VulnerabilityReport(
        id="real_v2",
        tool="bandit",
        rule_id="B608",
        severity="HIGH",
        confidence="HIGH",
        title="",
        description="",
        file_path="x.py",
        line_number=1,
        function_code=big,
        cwe_id="CWE-89",
    )
    cfg = LLMOptimizationConfig(max_context_chars=300)
    targets, _ = optimize_llm_targets([vr], cfg)
    assert len(targets[0].function_code) <= 300 + 80
    # 원본 function_code 는 그대로.
    assert vr.function_code == big


# ---------------------------------------------------------------------------
# 13. AST 순수성 가드
# ---------------------------------------------------------------------------


_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_MODULE_PATH = _REPO_ROOT / "shared" / "llm_optimization.py"

_FORBIDDEN_TOP_LEVEL_MODULES = {
    "os",
    "time",
    "subprocess",
    "requests",
    "httpx",
    "socket",
    "pathlib",
    "fastapi",
    "sqlalchemy",
    "pickle",
    "importlib",
}
_FORBIDDEN_FIRST_LEVEL_PACKAGES = {
    "api",
    "db",
    "analyzer",
    "agent",
    "validator",
    "dashboard",
}
_FORBIDDEN_CALL_NAMES = {"open", "Path", "eval", "exec"}
_FORBIDDEN_ATTR_PAIRS = {
    ("os", "system"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("pickle", "load"),
    ("pickle", "loads"),
    ("time", "time"),
    ("time", "sleep"),
}


def _parse_module() -> ast.AST:
    src = _MODULE_PATH.read_text(encoding="utf-8")
    return ast.parse(src)


def _top_level_name(dotted: str) -> str:
    return dotted.split(".")[0]


def test_module_purity_no_forbidden_imports():
    tree = _parse_module()
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = _top_level_name(alias.name)
                if (
                    top in _FORBIDDEN_TOP_LEVEL_MODULES
                    or top in _FORBIDDEN_FIRST_LEVEL_PACKAGES
                ):
                    offenders.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if not node.module:
                continue
            top = _top_level_name(node.module)
            if (
                top in _FORBIDDEN_TOP_LEVEL_MODULES
                or top in _FORBIDDEN_FIRST_LEVEL_PACKAGES
            ):
                offenders.append(node.module)
    assert not offenders, (
        f"shared/llm_optimization.py imports forbidden modules: {offenders}"
    )


def test_module_purity_no_forbidden_calls_or_attribute_use():
    tree = _parse_module()
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id in _FORBIDDEN_CALL_NAMES:
                offenders.append(f.id)
            elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                pair = (f.value.id, f.attr)
                if pair in _FORBIDDEN_ATTR_PAIRS:
                    offenders.append(".".join(pair))
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            pair = (node.value.id, node.attr)
            if pair in _FORBIDDEN_ATTR_PAIRS:
                offenders.append(".".join(pair))
    assert not offenders, (
        f"shared/llm_optimization.py contains forbidden calls/attribute accesses: {offenders}"
    )


def test_module_no_top_level_side_effects():
    """최상위에는 정의 / 상수 / docstring / import 외에 표현이 없다."""
    tree = _parse_module()
    allowed = (
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.ClassDef,
        ast.Assign,
        ast.AnnAssign,
        ast.AugAssign,
        ast.ImportFrom,
        ast.Import,
    )
    for stmt in tree.body:
        if isinstance(stmt, allowed):
            continue
        if (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str)
        ):
            continue
        raise AssertionError(
            f"top-level statement not allowed in shared/llm_optimization.py: {ast.dump(stmt)}"
        )


def test_module_does_not_contain_policy_tokens():
    """gateway / claude-sonnet / LLM_PRIMARY_PROVIDER 같은 정책 토큰은 본 wave 에서 금지."""
    src = _MODULE_PATH.read_text(encoding="utf-8").lower()
    forbidden_tokens = ["gateway", "claude-sonnet", "llm_primary_provider"]
    offenders = [t for t in forbidden_tokens if t in src]
    assert not offenders, (
        f"shared/llm_optimization.py contains forbidden policy tokens: {offenders}"
    )
