"""Quick scan match-mode policy seam tests (Wave 5-H2).

``analyzer/quick_scan.py`` 의 ``scan()`` 은 현재 룰의 ``patterns`` 중 하나라도
일치하면 finding 을 생성한다(legacy "any" 동작). 본 Wave 는 향후 룰이
"동일 라인에서 모든 패턴이 함께 매치되어야만 finding" 을 옵트인할 수 있도록
``match_mode`` / ``require_all`` 메타데이터 기반 policy seam 을 추가한다.

본 테스트는 production code 가 추가되기 전 RED 상태로 실패해야 하며 다음을
검증한다:

1. 메타데이터 미지정 시 legacy "any" 동작이 그대로 유지된다.
2. ``match_mode="any"`` 는 한 패턴만 매치되어도 finding 을 만든다 (legacy alias).
3. ``match_mode="all"`` 은 동일 라인에서 모든 패턴이 매치된 라인에만 finding 을
   만든다.
4. ``require_all=True`` 는 ``match_mode="all"`` 과 동일하게 동작한다.
5. 기존 실제 룰 ``QS-WEAK-HASH`` 의 python 매치 동작이 보존된다.
6. 언어 필터링과 finding shape 가 보존된다.
7. ``match_mode="all"`` 에서 패턴 중 하나라도 invalid regex 면 fail-closed
   (아무 finding 도 만들지 않음). all-pattern 룰이 깨졌을 때 매치 범위가
   조용히 넓어지지 않도록 한다.

테스트 격리:
- 매 테스트 후 ``analyzer.quick_scan.QUICK_SCAN_RULES`` 를 원본 list 로 복귀.
- FastAPI / DB / subprocess / network / settings / filesystem 의존성 없음.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import quick_scan as quick_scan_module


_FINDING_KEYS = {"rule_id", "title", "severity", "cwe", "line", "code", "message"}


@pytest.fixture(autouse=True)
def _restore_quick_scan_rules():
    """각 테스트 종료 시 production rule list 를 원본으로 복귀."""
    original = quick_scan_module.QUICK_SCAN_RULES
    yield
    quick_scan_module.QUICK_SCAN_RULES = original


def _install_rules(monkeypatch, rules):
    monkeypatch.setattr(quick_scan_module, "QUICK_SCAN_RULES", rules)


def _custom_rule(**overrides):
    """테스트 전용 더미 룰 ─ 실제 production 룰을 활성화하지 않는다."""
    base = {
        "id": "QS-TEST-RULE",
        "title": "테스트 전용 룰",
        "severity": "LOW",
        "cwe": "CWE-0",
        "patterns": [r"alpha", r"beta"],
        "languages": ["python"],
        "message": "테스트 전용 메시지",
    }
    base.update(overrides)
    return base


# ============================================================
# Test 1 — 메타데이터 미지정 시 legacy "any" 동작 보존
# ============================================================

def test_missing_metadata_defaults_to_legacy_any_behavior(monkeypatch):
    rule = _custom_rule(patterns=[r"alpha", r"beta"])
    # match_mode / require_all 모두 미지정.
    assert "match_mode" not in rule
    assert "require_all" not in rule
    _install_rules(monkeypatch, [rule])

    code = "alpha only here\nbeta only here\nneither here\n"
    findings = quick_scan_module.scan(code, "python")

    # alpha-only line(1), beta-only line(2) 두 줄 모두 finding 이 나와야 한다.
    lines = sorted(f["line"] for f in findings)
    assert lines == [1, 2], f"legacy any: 1행/2행 모두 finding 이어야 한다, got {lines}"
    for f in findings:
        assert f["rule_id"] == "QS-TEST-RULE"


# ============================================================
# Test 2 — match_mode="any" 가 legacy 동작과 동등
# ============================================================

def test_match_mode_any_matches_when_single_pattern_matches(monkeypatch):
    rule = _custom_rule(patterns=[r"alpha", r"beta"], match_mode="any")
    _install_rules(monkeypatch, [rule])

    code = "alpha standalone\nbeta standalone\n"
    findings = quick_scan_module.scan(code, "python")

    lines = sorted(f["line"] for f in findings)
    assert lines == [1, 2], (
        f"match_mode='any': 단일 패턴 매치 라인도 모두 finding 이어야 한다, got {lines}"
    )


# ============================================================
# Test 3 — match_mode="all" 은 동일 라인에서 모든 패턴이 매치된 라인만 finding
# ============================================================

def test_match_mode_all_requires_every_pattern_on_same_line(monkeypatch):
    rule = _custom_rule(
        id="QS-TEST-ALL",
        patterns=[r"alpha", r"beta"],
        match_mode="all",
    )
    _install_rules(monkeypatch, [rule])

    code = (
        "alpha only\n"                # line 1 — alpha 만
        "beta only\n"                 # line 2 — beta 만
        "alpha and beta together\n"   # line 3 — 둘 다
        "nothing here\n"              # line 4
    )
    findings = quick_scan_module.scan(code, "python")

    lines = sorted(f["line"] for f in findings)
    assert lines == [3], (
        f"match_mode='all': 모든 패턴이 동일 라인에 있는 행만 finding, got {lines}"
    )
    # 룰/라인당 단일 finding 보존
    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "QS-TEST-ALL"
    # finding shape 보존
    assert _FINDING_KEYS <= set(f.keys())
    assert f["code"] == "alpha and beta together"


# ============================================================
# Test 4 — require_all=True 가 match_mode="all" 의 alias
# ============================================================

def test_require_all_true_is_alias_for_all_pattern_matching(monkeypatch):
    rule = _custom_rule(
        id="QS-TEST-REQALL",
        patterns=[r"alpha", r"beta"],
        require_all=True,
    )
    _install_rules(monkeypatch, [rule])

    code = (
        "alpha only\n"
        "beta only\n"
        "alpha then beta\n"
        "beta-first alpha-second\n"
    )
    findings = quick_scan_module.scan(code, "python")

    lines = sorted(f["line"] for f in findings)
    assert lines == [3, 4], (
        f"require_all=True: 모든 패턴이 동일 라인에 있는 행만 finding, got {lines}"
    )
    for f in findings:
        assert f["rule_id"] == "QS-TEST-REQALL"


# ============================================================
# Test 5 — 실제 룰 QS-WEAK-HASH (python) 동작 보존
# ============================================================

def test_real_weak_hash_rule_still_triggers_on_python_md5():
    # production rules 그대로 사용 (monkeypatch 없음).
    code = "import hashlib\nhashlib.md5(b'x')\n"
    findings = quick_scan_module.scan(code, "python")

    weak = [f for f in findings if f["rule_id"] == "QS-WEAK-HASH"]
    assert weak, "QS-WEAK-HASH 룰이 python md5 호출에 대해 finding 을 생성해야 한다"
    assert weak[0]["line"] == 2
    assert _FINDING_KEYS <= set(weak[0].keys())


# ============================================================
# Test 6 — 언어 필터링과 finding shape 보존
# ============================================================

def test_language_filter_skips_non_listed_language(monkeypatch):
    rule = _custom_rule(patterns=[r"alpha"], languages=["python"])
    _install_rules(monkeypatch, [rule])

    # 룰은 python 전용 → java 호출 시 finding 없음.
    findings = quick_scan_module.scan("alpha\n", "java")
    assert findings == [], (
        f"languages 필터링: 비대상 언어에는 finding 이 없어야 한다, got {findings}"
    )

    # 같은 코드/룰을 python 으로 돌리면 finding 발생.
    findings_py = quick_scan_module.scan("alpha\n", "python")
    assert len(findings_py) == 1
    assert _FINDING_KEYS <= set(findings_py[0].keys())


def test_findings_sorted_by_line_and_one_per_rule_line(monkeypatch):
    rule = _custom_rule(patterns=[r"alpha"])
    _install_rules(monkeypatch, [rule])

    code = "alpha\nalpha\nalpha\n"
    findings = quick_scan_module.scan(code, "python")

    assert [f["line"] for f in findings] == [1, 2, 3]
    # rule/line 당 단일 finding (중복 패턴 매치에도 한 번만)
    pairs = [(f["rule_id"], f["line"]) for f in findings]
    assert len(pairs) == len(set(pairs))


# ============================================================
# Test 7 — match_mode="all" + invalid regex → fail-closed
# ============================================================

def test_match_mode_all_fails_closed_on_invalid_regex(monkeypatch):
    # 두 번째 패턴은 컴파일 실패하는 invalid regex.
    rule = _custom_rule(
        id="QS-TEST-ALL-BROKEN",
        patterns=[r"alpha", r"("],   # "(" 는 컴파일 실패
        match_mode="all",
    )
    _install_rules(monkeypatch, [rule])

    code = "alpha appears here\nalpha again\n"
    findings = quick_scan_module.scan(code, "python")

    assert findings == [], (
        "match_mode='all' 에서 invalid regex 가 포함되면 어떤 라인에서도 "
        "finding 을 만들지 않아야 한다 (fail-closed). "
        f"got {findings}"
    )
