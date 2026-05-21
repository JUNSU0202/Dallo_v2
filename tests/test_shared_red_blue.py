"""Wave 5-B shared/red_blue.py 단위 테스트.

본 테스트는 ``shared/red_blue.py`` 의 Red/Blue 도메인 enrichment 모듈의
행동 계약(behavioral contract)을 검증한다. 본 모듈은 순수 dict/list 도메인
헬퍼이며, 어떠한 실제 외부 도구도 호출하지 않는다 — FastAPI / DB / disk /
network / clock / subprocess / env / LLM 와 접점이 없다.

검증 항목:
- 알려진 CWE 템플릿 매트릭스 (CWE-89/78/79/798/328/502/22/288)
- 알려지지 않은 CWE 의 generic fallback (title -> rule_id 순)
- ``enrich_*`` 함수의 idempotency 와 비파괴(deepcopy) 보장
- ``enrich_patch`` 의 4 가지 outcome 경로
- ``build_red_blue_summary`` 의 상위 키 셋 / ``include_attack_paths`` 옵션
- ``build_defense_comparison`` 의 산수 (zero / clamp / introduced) 엣지 케이스
- ``build_attack_paths`` 의 상태 결정 / best-patch 우선순위
- 빈 id / vulnerability_id 충돌 회귀 가드
- 모듈 순수성 AST 가드 (금지된 import / call 0 건)
- 공개/내부 출력 dict 의 exact key set 검증
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from shared.red_blue import (
    build_attack_paths,
    build_defense_comparison,
    build_red_blue_summary,
    enrich_patch,
    enrich_vulnerability,
)


# ---------------------------------------------------------------------------
# 1. 알려진 CWE 템플릿 매트릭스
# ---------------------------------------------------------------------------

_CWE_TEMPLATE_MATRIX = {
    "CWE-89": "sql",
    "CWE-78": "command",
    "CWE-79": "cross-site",
    "CWE-798": "hardcoded",
    "CWE-328": "weak",
    "CWE-502": "deserialization",
    "CWE-22": "path",
    "CWE-288": "authentication",
}


@pytest.mark.parametrize("cwe_id,keyword", list(_CWE_TEMPLATE_MATRIX.items()))
def test_enrich_vulnerability_known_cwe_attack_vector_keyword(cwe_id, keyword):
    vuln = {"id": "v1", "cwe_id": cwe_id, "severity": "HIGH", "confidence": "HIGH"}
    out = enrich_vulnerability(vuln)
    assert keyword in out["attack_vector"].lower(), (
        f"CWE {cwe_id}: attack_vector expected to contain '{keyword}', "
        f"got {out['attack_vector']!r}"
    )
    # 알려진 CWE 는 generic scenario/impact 문구가 아니어야 한다.
    assert "increased application security risk" not in out["security_impact"]


def test_enrich_vulnerability_unknown_cwe_falls_back_to_title():
    vuln = {"id": "v1", "cwe_id": "CWE-9999", "title": "Some Custom Weakness"}
    out = enrich_vulnerability(vuln)
    assert "some custom weakness" in out["attack_vector"].lower()


def test_enrich_vulnerability_unknown_cwe_no_title_uses_rule_id():
    vuln = {"id": "v1", "cwe_id": "CWE-9999", "rule_id": "X-RULE-42"}
    out = enrich_vulnerability(vuln)
    assert "x-rule-42" in out["attack_vector"].lower()


def test_enrich_vulnerability_missing_cwe_completely():
    vuln = {"id": "v1", "title": "weird thing"}
    out = enrich_vulnerability(vuln)
    # cwe_id 가 아예 없어도 모듈이 죽지 않는다
    assert isinstance(out["attack_vector"], str) and out["attack_vector"]
    assert out["red_team_phase"] == "attack_surface_mapping"


# ---------------------------------------------------------------------------
# 2. 비파괴 / 멱등 보장
# ---------------------------------------------------------------------------

def test_enrich_vulnerability_is_idempotent():
    vuln = {"id": "v1", "cwe_id": "CWE-89", "severity": "HIGH", "confidence": "HIGH"}
    once = enrich_vulnerability(vuln)
    twice = enrich_vulnerability(once)
    assert once == twice


def test_enrich_vulnerability_does_not_mutate_input_including_nested():
    inner_evidence = {"snippet_lines": ["a", "b"]}
    vuln = {
        "id": "v1",
        "cwe_id": "CWE-89",
        "severity": "HIGH",
        "confidence": "HIGH",
        "nested_evidence": inner_evidence,
    }
    snapshot = {
        "id": "v1",
        "cwe_id": "CWE-89",
        "severity": "HIGH",
        "confidence": "HIGH",
        "nested_evidence": {"snippet_lines": ["a", "b"]},
    }
    out = enrich_vulnerability(vuln)
    assert vuln == snapshot, "input vuln dict was mutated by enrich_vulnerability"
    # 결과의 nested 를 caller 가 수정해도 원본은 안전해야 한다 (deepcopy 보장).
    out["nested_evidence"]["snippet_lines"].append("c")
    assert inner_evidence["snippet_lines"] == ["a", "b"]


def test_enrich_vulnerability_preserves_caller_provided_red_blue_keys():
    """setdefault 의미론: caller 가 이미 채운 Red/Blue 키는 절대 덮어쓰지 않는다."""
    vuln = {
        "id": "v1",
        "cwe_id": "CWE-89",
        "attack_vector": "custom-preserved",
        "exploitability": "low",
        "red_team_phase": "custom_phase",
    }
    out = enrich_vulnerability(vuln)
    assert out["attack_vector"] == "custom-preserved"
    assert out["exploitability"] == "low"
    assert out["red_team_phase"] == "custom_phase"


def test_enrich_patch_is_idempotent():
    patch = {
        "vulnerability_id": "v1",
        "fixed_code": "...",
        "syntax_valid": True,
        "security_revalidation": {"passed": True, "introduced_count": 0, "removed_count": 1},
    }
    once = enrich_patch(patch)
    twice = enrich_patch(once)
    assert once == twice


# ---------------------------------------------------------------------------
# 3. enrich_patch outcome 4 분기
# ---------------------------------------------------------------------------

def test_enrich_patch_outcome_validated_defense_when_revalidation_passed():
    patch = {
        "vulnerability_id": "v1",
        "fixed_code": "...",
        "syntax_valid": True,
        "security_revalidation": {"passed": True, "introduced_count": 0, "removed_count": 1},
        "status": "PatchStatus.VERIFIED",
    }
    out = enrich_patch(patch)
    assert out["defense_outcome"] == "validated_defense"
    assert out["residual_risk"] == "low"
    assert out["defense_plan"]["status"] == "BLOCKED"


def test_enrich_patch_outcome_validated_defense_when_status_verified_no_sec():
    patch = {
        "vulnerability_id": "v1",
        "fixed_code": "...",
        "status": "PatchStatus.VERIFIED",
    }
    out = enrich_patch(patch)
    assert out["defense_outcome"] == "validated_defense"


def test_enrich_patch_outcome_needs_review_when_introduced_count_positive():
    patch = {
        "vulnerability_id": "v1",
        "fixed_code": "...",
        "syntax_valid": True,
        "security_revalidation": {"passed": False, "introduced_count": 2, "removed_count": 0},
    }
    out = enrich_patch(patch)
    assert out["defense_outcome"] == "needs_review"
    assert out["residual_risk"] == "high"
    assert out["defense_plan"]["status"] == "REVIEW"


def test_enrich_patch_outcome_needs_review_when_status_failed():
    patch = {
        "vulnerability_id": "v1",
        "fixed_code": "...",
        "status": "PatchStatus.FAILED",
    }
    out = enrich_patch(patch)
    assert out["defense_outcome"] == "needs_review"


def test_enrich_patch_outcome_drafted_defense_when_only_fixed_code():
    patch = {"vulnerability_id": "v1", "fixed_code": "...", "syntax_valid": None}
    out = enrich_patch(patch)
    assert out["defense_outcome"] == "drafted_defense"
    assert out["residual_risk"] == "medium"
    assert out["defense_plan"]["status"] == "MITIGATING"


def test_enrich_patch_outcome_not_generated_when_no_fixed_code():
    patch = {"vulnerability_id": "v1"}
    out = enrich_patch(patch)
    assert out["defense_outcome"] == "not_generated"
    assert out["residual_risk"] == "unknown"
    assert out["defense_plan"]["status"] == "OPEN"


def test_enrich_patch_does_not_mutate_input_including_nested_security_revalidation():
    sec = {
        "passed": True,
        "introduced_count": 0,
        "removed_count": 1,
        "details": {"finding_ids": ["v1"]},
    }
    patch = {"vulnerability_id": "v1", "fixed_code": "...", "security_revalidation": sec}
    snapshot = {
        "vulnerability_id": "v1",
        "fixed_code": "...",
        "security_revalidation": {
            "passed": True,
            "introduced_count": 0,
            "removed_count": 1,
            "details": {"finding_ids": ["v1"]},
        },
    }
    out = enrich_patch(patch)
    assert patch == snapshot, "input patch dict was mutated by enrich_patch"
    # 결과의 nested security_revalidation 을 수정해도 원본은 안전해야 한다.
    out["security_revalidation"]["details"]["finding_ids"].append("v2")
    assert sec["details"]["finding_ids"] == ["v1"]


def test_enrich_patch_with_none_vuln_uses_generic_fallback_strategy():
    patch = {"vulnerability_id": "v1", "fixed_code": "...", "syntax_valid": True}
    out = enrich_patch(patch, None)
    assert isinstance(out["defense_strategy"], str) and out["defense_strategy"]
    assert out["defense_outcome"] == "drafted_defense"
    # 명시 vuln 이 없어도 defense_plan 이 정상 구축되어야 한다.
    plan = out["defense_plan"]
    assert plan["status"] == "MITIGATING"
    assert plan["finding_id"] == "v1"


# ---------------------------------------------------------------------------
# 4. build_red_blue_summary
# ---------------------------------------------------------------------------

def test_build_red_blue_summary_default_top_level_keys():
    vulns = [
        {"id": "v1", "cwe_id": "CWE-89", "severity": "HIGH", "file_path": "a.py"},
        {"id": "v2", "cwe_id": "CWE-78", "severity": "MEDIUM", "file_path": "b.py"},
    ]
    patches = [
        {
            "vulnerability_id": "v1",
            "fixed_code": "...",
            "security_revalidation": {"passed": True, "removed_count": 1, "introduced_count": 0},
        },
    ]
    out = build_red_blue_summary(vulns, patches)
    assert set(out.keys()) == {"red_team", "blue_team", "comparison"}
    assert out["red_team"]["total_findings"] == 2
    assert out["red_team"]["critical_or_high"] == 1
    assert out["red_team"]["unique_cwe"] == 2
    assert out["red_team"]["affected_files"] == 2
    assert out["blue_team"]["patches_generated"] == 1
    assert out["blue_team"]["patches_verified"] == 1
    assert out["blue_team"]["patches_needing_review"] == 0


def test_build_red_blue_summary_include_attack_paths_adds_only_attack_paths_key():
    vulns = [{"id": "v1", "cwe_id": "CWE-89"}]
    out = build_red_blue_summary(vulns, [], include_attack_paths=True)
    assert set(out.keys()) == {"red_team", "blue_team", "comparison", "attack_paths"}
    assert isinstance(out["attack_paths"], list)
    assert len(out["attack_paths"]) == 1


def test_build_red_blue_summary_default_excludes_attack_paths():
    vulns = [{"id": "v1", "cwe_id": "CWE-89"}]
    out = build_red_blue_summary(vulns, [])
    assert "attack_paths" not in out


def test_build_red_blue_summary_no_legacy_top_level_marker_keys():
    """Wave 5-A 결정: ``mode`` / ``system_label`` / ``analysis_mode`` 같은
    응답 contract 의 최상위 마커 키를 본 wave 에서 도입하지 않는다."""
    out = build_red_blue_summary([], [])
    forbidden = {"mode", "system_label", "analysis_mode"}
    assert forbidden.isdisjoint(out.keys()), (
        f"summary must not include legacy top-level marker keys, got "
        f"{sorted(out.keys())}"
    )


def test_build_red_blue_summary_does_not_mutate_inputs():
    vulns = [{"id": "v1", "cwe_id": "CWE-89", "severity": "HIGH"}]
    patches = [{"vulnerability_id": "v1", "fixed_code": "..."}]
    vulns_snapshot = [{"id": "v1", "cwe_id": "CWE-89", "severity": "HIGH"}]
    patches_snapshot = [{"vulnerability_id": "v1", "fixed_code": "..."}]
    build_red_blue_summary(vulns, patches, include_attack_paths=True)
    assert vulns == vulns_snapshot
    assert patches == patches_snapshot


# ---------------------------------------------------------------------------
# 5. build_defense_comparison
# ---------------------------------------------------------------------------

def test_build_defense_comparison_zero_before_total():
    out = build_defense_comparison([], [])
    assert out["before_total"] == 0
    assert out["after_total"] == 0
    assert out["fixed_count"] == 0
    assert out["remaining_count"] == 0
    assert out["introduced_count"] == 0
    assert out["risk_reduction_percent"] == 0.0
    assert isinstance(out["risk_reduction_percent"], float)


def test_build_defense_comparison_removed_clamped_to_before_total():
    """sec.removed_count 가 before_total 보다 크면 clamp 되어 음수 카운트가 나오지 않는다."""
    vulns = [{"id": "v1"}]
    patches = [
        {
            "vulnerability_id": "v1",
            "fixed_code": "...",
            "security_revalidation": {
                "removed_count": 5,
                "introduced_count": 0,
                "passed": True,
            },
        },
    ]
    out = build_defense_comparison(vulns, patches)
    assert out["fixed_count"] == 1  # 5 -> clamp -> 1
    assert out["remaining_count"] == 0
    assert out["after_total"] == 0
    assert out["risk_reduction_percent"] == 100.0


def test_build_defense_comparison_introduced_count_tracked_and_added_to_after():
    vulns = [{"id": "v1"}, {"id": "v2"}]
    patches = [
        {
            "vulnerability_id": "v1",
            "fixed_code": "...",
            "security_revalidation": {
                "removed_count": 1,
                "introduced_count": 3,
                "passed": False,
            },
        },
    ]
    out = build_defense_comparison(vulns, patches)
    assert out["before_total"] == 2
    assert out["introduced_count"] == 3
    assert out["fixed_count"] == 1
    assert out["remaining_count"] == 1
    assert out["after_total"] == 2 - 1 + 3
    assert out["risk_reduction_percent"] == 50.0


def test_build_defense_comparison_validated_defense_without_sec_counts_as_removed():
    """sec 가 없어도 enriched patch 의 defense_outcome == validated_defense 면 1 건 차감."""
    vulns = [{"id": "v1"}, {"id": "v2"}]
    # 미리 enrich 하여 defense_outcome 을 명시적으로 설정한다.
    raw = {"vulnerability_id": "v1", "fixed_code": "...", "status": "PatchStatus.VERIFIED"}
    enriched = enrich_patch(raw)
    out = build_defense_comparison(vulns, [enriched])
    assert out["fixed_count"] == 1
    assert out["remaining_count"] == 1


def test_build_defense_comparison_rounding_to_one_decimal():
    vulns = [{"id": f"v{i}"} for i in range(3)]
    patches = [
        {
            "vulnerability_id": "v1",
            "fixed_code": "...",
            "security_revalidation": {"passed": True, "removed_count": 1, "introduced_count": 0},
        },
    ]
    out = build_defense_comparison(vulns, patches)
    # 1/3 * 100 = 33.333... -> 33.3
    assert out["risk_reduction_percent"] == 33.3


# ---------------------------------------------------------------------------
# 5b. Wave 5-N — e474680 회귀: verified 패치인데 removed_count=0 인 경우 보정
# ---------------------------------------------------------------------------
#
# 배경:
#   Bandit/Semgrep 같은 도구 비교 단계에서 패치 코드의 라인 매핑이 달라져
#   ``security_revalidation.removed_count`` 가 0 으로 보고될 수 있다.
#   그러나 ``security_revalidation.passed == True`` 이고 ``fixed_code`` 가
#   실제로 생성된 상태라면 도메인적으로 "방어가 검증됐다" 가 맞고, 비교 누락
#   하나로 risk_reduction_percent 가 0% 로 보고되는 회귀를 막아야 한다.
#   (e474680: fix: generate blue team patches for audit findings)
#

def test_build_defense_comparison_verified_with_zero_removed_count_corrects_to_one():
    """passed=True + removed_count=0 + fixed_code → 1 건 fixed 로 보정."""
    vulns = [{"id": "v1", "cwe_id": "CWE-89"}]
    patches = [
        {
            "vulnerability_id": "v1",
            "fixed_code": "SAFE_CODE",
            "security_revalidation": {
                "passed": True,
                "removed_count": 0,
                "introduced_count": 0,
            },
        },
    ]
    out = build_defense_comparison(vulns, patches)
    assert out["fixed_count"] == 1, (
        f"passed+fixed_code 인데 fixed_count 가 0 — 비교 누락이 보정되지 않음: {out}"
    )
    assert out["remaining_count"] == 0
    assert out["risk_reduction_percent"] == 100.0


def test_build_red_blue_summary_verified_zero_removed_blocks_attack_path():
    """동일 조건에서 attack_paths[0].status == 'BLOCKED' (방어 검증)."""
    vulns = [{"id": "v1", "cwe_id": "CWE-89"}]
    patches = [
        {
            "vulnerability_id": "v1",
            "fixed_code": "SAFE_CODE",
            "security_revalidation": {
                "passed": True,
                "removed_count": 0,
                "introduced_count": 0,
            },
        },
    ]
    summary = build_red_blue_summary(vulns, patches, include_attack_paths=True)
    assert summary["comparison"]["fixed_count"] == 1
    assert summary["comparison"]["risk_reduction_percent"] == 100.0
    assert summary["blue_team"]["patches_verified"] == 1
    assert summary["attack_paths"][0]["status"] == "BLOCKED"


def test_build_defense_comparison_passed_zero_removed_no_fixed_code_not_corrected():
    """``fixed_code`` 가 없으면 보정하지 않는다 — 정말 빈 패치를 1 건으로 부풀리면 안 된다."""
    vulns = [{"id": "v1"}]
    patches = [
        {
            "vulnerability_id": "v1",
            "fixed_code": "",
            "security_revalidation": {
                "passed": True,
                "removed_count": 0,
                "introduced_count": 0,
            },
        },
    ]
    out = build_defense_comparison(vulns, patches)
    assert out["fixed_count"] == 0
    assert out["risk_reduction_percent"] == 0.0


# ---------------------------------------------------------------------------
# 5c. Wave 5-N — e474680 회귀: enrich_patch 가 빈 문자열 Blue Team 필드를 채운다
# ---------------------------------------------------------------------------
#
# 배경:
#   ``PatchSuggestion.to_dict()`` 또는 외부 직렬화 경로가 Blue Team 키를
#   빈 문자열 ``""`` 로 미리 채워서 보낼 수 있다. ``setdefault`` 는 키가
#   *없을* 때만 default 를 채우므로 빈 문자열은 그대로 남아 대시보드가
#   "verified=0" 으로 잘못 보고하는 회귀가 발생했다. ``if not item.get(...)``
#   falsy 체크로 빈 문자열도 채워지도록 한다 (e474680).
#

def test_enrich_patch_fills_empty_string_blue_team_phase():
    patch = {
        "vulnerability_id": "v1",
        "fixed_code": "SAFE",
        "blue_team_phase": "",
    }
    out = enrich_patch(patch)
    assert out["blue_team_phase"] == "remediation"


def test_enrich_patch_fills_empty_string_defense_strategy():
    patch = {
        "vulnerability_id": "v1",
        "fixed_code": "SAFE",
        "defense_strategy": "",
    }
    out = enrich_patch(patch)
    assert isinstance(out["defense_strategy"], str)
    assert out["defense_strategy"], "defense_strategy 가 여전히 빈 문자열로 남아 있다"


def test_enrich_patch_fills_empty_string_defense_outcome():
    patch = {
        "vulnerability_id": "v1",
        "fixed_code": "SAFE",
        "syntax_valid": True,
        "security_revalidation": {"passed": True, "removed_count": 1, "introduced_count": 0},
        "defense_outcome": "",
    }
    out = enrich_patch(patch)
    assert out["defense_outcome"] == "validated_defense"


def test_enrich_patch_fills_empty_string_residual_risk():
    patch = {
        "vulnerability_id": "v1",
        "fixed_code": "SAFE",
        "syntax_valid": True,
        "security_revalidation": {"passed": True, "removed_count": 1, "introduced_count": 0},
        "residual_risk": "",
    }
    out = enrich_patch(patch)
    assert out["residual_risk"] == "low"


def test_enrich_patch_fills_empty_dict_defense_plan():
    patch = {
        "vulnerability_id": "v1",
        "fixed_code": "SAFE",
        "syntax_valid": True,
        "security_revalidation": {"passed": True, "removed_count": 1, "introduced_count": 0},
        "defense_plan": {},
    }
    out = enrich_patch(patch)
    plan = out["defense_plan"]
    assert isinstance(plan, dict) and plan, "defense_plan 이 여전히 빈 dict 로 남아 있다"
    assert plan["status"] == "BLOCKED"


def test_enrich_patch_preserves_caller_truthy_blue_team_values():
    """이미 caller 가 채운 truthy 값은 falsy 체크로 보존된다 (idempotency)."""
    patch = {
        "vulnerability_id": "v1",
        "fixed_code": "SAFE",
        "blue_team_phase": "custom_phase",
        "defense_strategy": "custom_strategy",
        "defense_outcome": "validated_defense",
        "residual_risk": "low",
        "defense_plan": {"finding_id": "v1", "status": "BLOCKED"},
    }
    out = enrich_patch(patch)
    assert out["blue_team_phase"] == "custom_phase"
    assert out["defense_strategy"] == "custom_strategy"
    assert out["defense_outcome"] == "validated_defense"
    assert out["residual_risk"] == "low"
    assert out["defense_plan"] == {"finding_id": "v1", "status": "BLOCKED"}


# ---------------------------------------------------------------------------
# 6. build_attack_paths
# ---------------------------------------------------------------------------

def test_build_attack_paths_no_patches_arg_open_high():
    vulns = [
        {
            "id": "v1",
            "cwe_id": "CWE-89",
            "rule_id": "B608",
            "title": "SQL injection",
            "file_path": "x.py",
            "line_number": 42,
        }
    ]
    rows = build_attack_paths(vulns, None)
    assert len(rows) == 1
    row = rows[0]
    assert row["status"] == "OPEN"
    assert row["residual_risk"] == "high"
    assert row["finding_id"] == "v1"
    assert row["rule_id"] == "B608"
    assert row["title"] == "SQL injection"
    assert row["cwe_id"] == "CWE-89"
    assert row["file_path"] == "x.py"
    assert row["line_number"] == 42
    assert isinstance(row["defense"], str) and row["defense"]


def test_build_attack_paths_empty_list_patches_open_high():
    vulns = [{"id": "v1", "cwe_id": "CWE-89"}]
    rows = build_attack_paths(vulns, [])
    assert rows[0]["status"] == "OPEN"
    assert rows[0]["residual_risk"] == "high"


def test_build_attack_paths_validated_patch_blocks_attack():
    vulns = [{"id": "v1", "cwe_id": "CWE-89"}]
    patches = [
        {
            "vulnerability_id": "v1",
            "fixed_code": "...",
            "security_revalidation": {"passed": True, "removed_count": 1, "introduced_count": 0},
        },
    ]
    rows = build_attack_paths(vulns, patches)
    assert rows[0]["status"] == "BLOCKED"
    assert rows[0]["residual_risk"] == "low"


def test_build_attack_paths_best_patch_picks_validated_over_drafted():
    vulns = [{"id": "v1", "cwe_id": "CWE-89"}]
    patches = [
        # drafted_defense only
        {"vulnerability_id": "v1", "fixed_code": "abc"},
        # validated_defense
        {
            "vulnerability_id": "v1",
            "fixed_code": "xyz",
            "security_revalidation": {"passed": True, "removed_count": 1, "introduced_count": 0},
        },
    ]
    rows = build_attack_paths(vulns, patches)
    assert rows[0]["status"] == "BLOCKED"
    assert rows[0]["residual_risk"] == "low"


def test_build_attack_paths_best_patch_picks_drafted_over_needs_review():
    vulns = [{"id": "v1", "cwe_id": "CWE-89"}]
    patches = [
        # needs_review (introduced security issue)
        {
            "vulnerability_id": "v1",
            "fixed_code": "a",
            "security_revalidation": {"introduced_count": 2, "removed_count": 0, "passed": False},
        },
        # drafted_defense
        {"vulnerability_id": "v1", "fixed_code": "b"},
    ]
    rows = build_attack_paths(vulns, patches)
    # drafted (priority 1) < needs_review (priority 2)
    assert rows[0]["status"] == "MITIGATING"


def test_build_attack_paths_best_patch_picks_needs_review_over_not_generated():
    vulns = [{"id": "v1", "cwe_id": "CWE-89"}]
    patches = [
        # not_generated
        {"vulnerability_id": "v1"},
        # needs_review (failed status)
        {"vulnerability_id": "v1", "fixed_code": "x", "status": "PatchStatus.FAILED"},
    ]
    rows = build_attack_paths(vulns, patches)
    assert rows[0]["status"] == "REVIEW"


def test_build_attack_paths_does_not_mutate_inputs():
    vulns = [{"id": "v1", "cwe_id": "CWE-89"}]
    patches = [{"vulnerability_id": "v1", "fixed_code": "..."}]
    vulns_snapshot = [{"id": "v1", "cwe_id": "CWE-89"}]
    patches_snapshot = [{"vulnerability_id": "v1", "fixed_code": "..."}]
    build_attack_paths(vulns, patches)
    assert vulns == vulns_snapshot
    assert patches == patches_snapshot


# ---------------------------------------------------------------------------
# 7. 빈 id 충돌 회귀
# ---------------------------------------------------------------------------

def test_build_attack_paths_empty_ids_do_not_collide_via_patch_map():
    """빈 ``id`` / ``vulnerability_id`` 가 같은 빈 문자열 키로 매칭되지 않아야 한다.

    Naive 한 ``patch_map = {p["vulnerability_id"]: p for p in patches}`` 구현
    에서는 모든 빈 id vuln 이 빈 vid 패치에 매칭되어 BLOCKED 로 보고된다.
    이는 데이터 품질 결함(빈 id 가 들어옴)을 가짜 방어 성공으로 보고하게 만든다.
    """
    vulns = [
        {"id": "", "cwe_id": "CWE-89"},
        {"id": "", "cwe_id": "CWE-78"},
    ]
    patches = [
        {
            "vulnerability_id": "",
            "fixed_code": "...",
            "security_revalidation": {"passed": True},
        },
    ]
    rows = build_attack_paths(vulns, patches)
    assert all(r["status"] == "OPEN" for r in rows), [r["status"] for r in rows]
    assert all(r["residual_risk"] == "high" for r in rows)


def test_build_red_blue_summary_empty_ids_do_not_collide():
    """``build_red_blue_summary`` 내부 patch_map 도 빈 id 충돌이 없어야 한다."""
    vulns = [
        {"id": "", "cwe_id": "CWE-89"},
        {"id": "", "cwe_id": "CWE-78"},
    ]
    patches = [
        {"vulnerability_id": "", "fixed_code": "...",
         "security_revalidation": {"passed": True, "removed_count": 1, "introduced_count": 0}},
    ]
    out = build_red_blue_summary(vulns, patches, include_attack_paths=True)
    assert all(r["status"] == "OPEN" for r in out["attack_paths"])


# ---------------------------------------------------------------------------
# 8. Exact key set 검증
# ---------------------------------------------------------------------------

_RED_BLUE_ADDED_KEYS = {
    "red_team_phase",
    "attack_vector",
    "attack_scenario",
    "security_impact",
    "blue_team_strategy",
    "exploitability",
    "attack_plan",
}


def test_enrich_vulnerability_adds_only_documented_red_blue_keys():
    vuln = {"id": "v1", "cwe_id": "CWE-89", "severity": "HIGH"}
    out = enrich_vulnerability(vuln)
    assert _RED_BLUE_ADDED_KEYS.issubset(out.keys())
    assert {"id", "cwe_id", "severity"}.issubset(out.keys())
    assert out["red_team_phase"] == "attack_surface_mapping"
    assert out["exploitability"] in {"high", "medium", "low"}


def test_attack_plan_exact_key_set_no_status():
    vuln = {"id": "v1", "cwe_id": "CWE-89", "severity": "HIGH"}
    out = enrich_vulnerability(vuln)
    plan = out["attack_plan"]
    expected = {
        "finding_id",
        "attack_goal",
        "entry_point",
        "controlled_input",
        "trust_boundary",
        "vulnerable_action",
        "exploit_steps",
        "impact",
        "evidence",
        "attack_path",
    }
    assert set(plan.keys()) == expected
    assert "status" not in plan, (
        "attack_plan must not include the `status` key in Wave 5-B contract"
    )
    assert isinstance(plan["exploit_steps"], list)
    assert all(isinstance(step, str) for step in plan["exploit_steps"])


_BLUE_ADDED_KEYS = {
    "blue_team_phase",
    "defense_strategy",
    "defense_outcome",
    "residual_risk",
    "defense_plan",
}


def test_enrich_patch_adds_only_documented_blue_keys():
    patch = {"vulnerability_id": "v1", "fixed_code": "..."}
    out = enrich_patch(patch)
    assert _BLUE_ADDED_KEYS.issubset(out.keys())
    assert {"vulnerability_id", "fixed_code"}.issubset(out.keys())
    assert out["blue_team_phase"] == "remediation"
    assert out["defense_outcome"] in {
        "validated_defense",
        "needs_review",
        "drafted_defense",
        "not_generated",
    }
    assert out["residual_risk"] in {"low", "medium", "high", "unknown"}


def test_defense_plan_exact_key_set():
    patch = {"vulnerability_id": "v1", "fixed_code": "..."}
    out = enrich_patch(patch)
    plan = out["defense_plan"]
    expected = {
        "finding_id",
        "status",
        "defense_goal",
        "strategy",
        "code_change",
        "validation",
        "residual_risk",
        "blocked_attack_path",
    }
    assert set(plan.keys()) == expected
    assert plan["status"] in {"BLOCKED", "MITIGATING", "REVIEW", "OPEN"}
    assert isinstance(plan["validation"], list)
    assert all(isinstance(s, str) for s in plan["validation"])
    # validation 은 syntax_check 와 security_revalidation 두 단계를 모두 다룬다.
    joined = "|".join(plan["validation"])
    assert "syntax_check" in joined
    assert "security_revalidation" in joined


def test_red_team_summary_exact_key_set():
    out = build_red_blue_summary([], [])
    expected = {"total_findings", "critical_or_high", "unique_cwe", "affected_files"}
    assert set(out["red_team"].keys()) == expected


def test_blue_team_summary_exact_key_set():
    out = build_red_blue_summary([], [])
    expected = {"patches_generated", "patches_verified", "patches_needing_review"}
    assert set(out["blue_team"].keys()) == expected


def test_defense_comparison_exact_key_set():
    out = build_defense_comparison([], [])
    expected = {
        "before_total",
        "after_total",
        "fixed_count",
        "remaining_count",
        "introduced_count",
        "risk_reduction_percent",
    }
    assert set(out.keys()) == expected


def test_attack_paths_row_exact_key_set():
    vulns = [{"id": "v1", "cwe_id": "CWE-89"}]
    rows = build_attack_paths(vulns, [])
    expected = {
        "finding_id",
        "rule_id",
        "title",
        "cwe_id",
        "file_path",
        "line_number",
        "attack_path",
        "attack_goal",
        "status",
        "defense",
        "residual_risk",
    }
    assert set(rows[0].keys()) == expected


# ---------------------------------------------------------------------------
# 9. 모듈 순수성 AST 가드
# ---------------------------------------------------------------------------

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_MODULE_PATH = _REPO_ROOT / "shared" / "red_blue.py"

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
}
_FORBIDDEN_FIRST_LEVEL_PACKAGES = {
    "analyzer",
    "api",
    "db",
    "agent",
    "reports",
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
    assert not offenders, f"shared/red_blue.py imports forbidden modules: {offenders}"


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
        f"shared/red_blue.py contains forbidden calls/attribute accesses: {offenders}"
    )


def test_module_no_top_level_side_effects():
    """모듈 최상위에는 정의 / 상수 할당 / docstring 외에 부수효과 표현이 없다."""
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
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) \
                and isinstance(stmt.value.value, str):
            # module docstring 만 Expr 로 허용
            continue
        raise AssertionError(
            f"top-level statement not allowed in shared/red_blue.py: {ast.dump(stmt)}"
        )


def test_shared_init_does_not_export_private_helpers():
    """``shared/__init__.py`` 가 red_blue 의 private 헬퍼를 재노출하지 않아야 한다."""
    init_src = (_REPO_ROOT / "shared" / "__init__.py").read_text(encoding="utf-8")
    for name in ("_build_attack_plan", "_build_defense_plan", "_ATTACK_TEMPLATES"):
        assert name not in init_src
