"""Heuristic fallback pure helper tests (Wave 5-H3).

본 Wave 는 `analyzer/heuristic_runner.py` 라는 **순수(side-effect free) heuristic
스캐너** 를 도입한다. 향후 fallback 경로에서 호출될 후보지만 본 wave 에서는
production 호출자 0건(caller 0) — tests 만 import 한다.

본 테스트 파일은 production 코드(`analyzer/heuristic_runner.py`) 가 추가되기
전에 RED 로 실패해야 한다. 다음을 잠근다.

1. 모듈/`scan_text` API 존재.
2. 기본 (rules=None) 호출 시 `analyzer.quick_scan.QUICK_SCAN_RULES` 를 그대로
   재사용하여 SQL injection / command injection / hardcoded secret / weak hash
   계열 finding 을 생성한다.
3. finding shape (rule_id/title/severity/cwe/line/code/message) 가
   quick_scan 과 동일하다.
4. `languages` 필드 기반 언어 필터링이 동작한다.
5. 커스텀 `match_mode="all"` / `require_all=True` 룰이 동일 라인에 모든 패턴이
   매치된 경우에만 finding 을 만들고, invalid regex 가 섞이면 fail-closed 다.
6. any-mode 룰에서 invalid regex 패턴은 조용히 스킵된다 (다른 패턴은 계속).
7. caller-owned 룰 list / 룰 dict / `patterns` list 는 mutate 되지 않는다.
8. `heuristic_runner` 는 production 경로 (`analyzer/quick_scan.py`,
   `analyzer/pipeline.py`, `analyzer/semgrep_runner.py`, `api/`, `agent/`,
   `validator/`, `db/`, `dashboard/`) 어디에서도 import 되지 않는다 (caller 0).
9. `analyzer/heuristic_runner.py` 소스에 금지 패턴 (open(/os.walk/subprocess/
   requests/time./datetime/FastAPI/api.server/DALLO_/os.environ/eval(/exec(/
   pickle.loads/shell=True) 가 등장하지 않는다.
10. `shared/schemas.py` 는 본 wave 에서 `heuristic_runner` 를 알지 못한다
    (즉 계약 파일 변경 없음).

테스트 격리:
- production `QUICK_SCAN_RULES` 를 변경하지 않는다. 커스텀 룰은 함수 인자로만
  전달한다 (helper 의 `rules=` 파라미터를 통해서).
- FastAPI / DB / subprocess / network / settings / filesystem (외부) 의존
  없음. shared filesystem read 는 본 테스트 파일 내부에서 worktree 안의
  소스 파일을 읽는 정적 가드 용으로만 사용한다.
"""

from __future__ import annotations

import copy
import os
import pathlib
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# RED 단계에서는 이 import 자체가 실패하여 모든 테스트가 ERROR 로 표시된다.
from analyzer import heuristic_runner  # noqa: E402
from analyzer import quick_scan as quick_scan_module  # noqa: E402


_FINDING_KEYS = {"rule_id", "title", "severity", "cwe", "line", "code", "message"}
_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _custom_rule(**overrides):
    base = {
        "id": "HR-TEST-RULE",
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
# Test 1 — public API 존재
# ============================================================

def test_scan_text_is_public_callable():
    assert hasattr(heuristic_runner, "scan_text"), (
        "analyzer.heuristic_runner 는 scan_text 헬퍼를 노출해야 한다"
    )
    assert callable(heuristic_runner.scan_text)


# ============================================================
# Test 2 — default rules (None) 가 production QUICK_SCAN_RULES 재사용
# ============================================================

def test_default_rules_detect_weak_hash_md5_call():
    code = "import hashlib\nhashlib.md5(b'x')\n"
    findings = heuristic_runner.scan_text(code, "python")

    weak = [f for f in findings if f["rule_id"] == "QS-WEAK-HASH"]
    assert weak, "기본 룰 셋이 hashlib.md5 호출을 감지해야 한다"
    assert weak[0]["line"] == 2


def test_default_rules_detect_sql_injection_fstring():
    # f-string 안에 SELECT 가 들어가고 ``{`` placeholder 가 있는 형태.
    code = 'q = f"SELECT * FROM users WHERE id={uid}"\n'
    findings = heuristic_runner.scan_text(code, "python")

    sqli = [f for f in findings if f["rule_id"] == "QS-SQL-INJECT"]
    assert sqli, "기본 룰 셋이 f-string SQL injection 을 감지해야 한다"


def test_default_rules_detect_command_injection_concat():
    code = 'import os\nos.system("ls " + user_input)\n'
    findings = heuristic_runner.scan_text(code, "python")

    cmd = [f for f in findings if f["rule_id"] == "QS-CMD-INJECT"]
    assert cmd, "기본 룰 셋이 os.system 문자열 결합 패턴을 감지해야 한다"


def test_default_rules_detect_hardcoded_secret_prefix():
    # 테스트 소스 안에 secret-like 리터럴이 연속으로 등장하지 않도록 prefix 를
    # 조립해서 만든다. (Dallo 자체 secret scan 자기-매치 회피.)
    prefix = "AIza" + "Sy"
    secret_like = prefix + "abcdef0123456789"
    code = "google = '" + secret_like + "'\n"
    findings = heuristic_runner.scan_text(code, "python")

    sec = [f for f in findings if f["rule_id"] == "QS-HARDCODED-SECRET"]
    assert sec, "기본 룰 셋이 prefix-style hardcoded secret 을 감지해야 한다"


# ============================================================
# Test 3 — finding shape 가 quick_scan 과 동일
# ============================================================

def test_finding_shape_matches_quick_scan_keys():
    code = "import hashlib\nhashlib.md5(b'x')\n"
    findings = heuristic_runner.scan_text(code, "python")
    assert findings, "최소 1개의 finding 이 있어야 shape 검증이 의미를 가진다"
    for f in findings:
        assert set(f.keys()) == _FINDING_KEYS, (
            f"finding key set 이 quick_scan 과 동일해야 한다, got {sorted(f.keys())}"
        )
        # 값 형 검증
        assert isinstance(f["rule_id"], str)
        assert isinstance(f["title"], str)
        assert isinstance(f["severity"], str)
        assert isinstance(f["cwe"], str)
        assert isinstance(f["line"], int)
        assert isinstance(f["code"], str)
        assert isinstance(f["message"], str)


def test_findings_sorted_by_line():
    rule = _custom_rule(patterns=[r"alpha"])
    code = "alpha\nalpha\nalpha\n"
    findings = heuristic_runner.scan_text(code, "python", rules=[rule])
    assert [f["line"] for f in findings] == [1, 2, 3]


# ============================================================
# Test 4 — 언어 필터링
# ============================================================

def test_language_filter_excludes_non_listed_language():
    rule = _custom_rule(patterns=[r"alpha"], languages=["python"])
    findings = heuristic_runner.scan_text("alpha\n", "java", rules=[rule])
    assert findings == [], (
        "languages 에 포함되지 않은 언어에는 finding 이 생성되지 않아야 한다, "
        f"got {findings}"
    )


def test_language_filter_includes_listed_language():
    rule = _custom_rule(patterns=[r"alpha"], languages=["python"])
    findings = heuristic_runner.scan_text("alpha\n", "python", rules=[rule])
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "HR-TEST-RULE"


# ============================================================
# Test 5 — match_mode="all" / require_all=True 동작 + fail-closed
# ============================================================

def test_all_mode_requires_every_pattern_on_same_line():
    rule = _custom_rule(
        id="HR-TEST-ALL",
        patterns=[r"alpha", r"beta"],
        match_mode="all",
    )
    code = (
        "alpha only\n"
        "beta only\n"
        "alpha and beta together\n"
        "nothing here\n"
    )
    findings = heuristic_runner.scan_text(code, "python", rules=[rule])
    lines = sorted(f["line"] for f in findings)
    assert lines == [3], (
        f"match_mode='all': 모든 패턴이 동일 라인에 있는 행만 finding, got {lines}"
    )
    assert findings[0]["rule_id"] == "HR-TEST-ALL"
    assert findings[0]["code"] == "alpha and beta together"


def test_require_all_true_is_alias_for_all_mode():
    rule = _custom_rule(
        id="HR-TEST-REQALL",
        patterns=[r"alpha", r"beta"],
        require_all=True,
    )
    code = (
        "alpha only\n"
        "beta only\n"
        "alpha then beta\n"
        "beta-first alpha-second\n"
    )
    findings = heuristic_runner.scan_text(code, "python", rules=[rule])
    lines = sorted(f["line"] for f in findings)
    assert lines == [3, 4]
    for f in findings:
        assert f["rule_id"] == "HR-TEST-REQALL"


def test_all_mode_fails_closed_on_invalid_regex():
    # 두 번째 패턴이 컴파일 실패하는 invalid regex → 룰 전체 스킵.
    rule = _custom_rule(
        id="HR-TEST-ALL-BROKEN",
        patterns=[r"alpha", r"("],
        match_mode="all",
    )
    code = "alpha here\nalpha again\n"
    findings = heuristic_runner.scan_text(code, "python", rules=[rule])
    assert findings == [], (
        "match_mode='all' 에서 invalid regex 가 포함되면 어떤 라인에서도 "
        f"finding 을 만들지 않아야 한다 (fail-closed). got {findings}"
    )


# ============================================================
# Test 6 — any-mode invalid regex 는 조용히 스킵
# ============================================================

def test_any_mode_skips_invalid_pattern_but_keeps_valid_one():
    rule = _custom_rule(
        id="HR-TEST-ANY-PARTIAL",
        patterns=[r"(", r"good"],  # 첫 패턴은 invalid, 두 번째는 valid
        # match_mode 미지정 → legacy any
    )
    code = "good stuff here\nno match here\n"
    findings = heuristic_runner.scan_text(code, "python", rules=[rule])
    assert len(findings) == 1, (
        f"any-mode: invalid regex 는 스킵되고 valid 패턴만 평가되어야 한다, "
        f"got {findings}"
    )
    assert findings[0]["line"] == 1
    assert findings[0]["rule_id"] == "HR-TEST-ANY-PARTIAL"


# ============================================================
# Test 7 — caller-owned 입력은 mutate 되지 않는다
# ============================================================

def test_caller_owned_rules_list_is_not_mutated():
    rule = _custom_rule(patterns=[r"alpha"])
    rules_arg = [rule]
    snapshot = copy.deepcopy(rules_arg)

    heuristic_runner.scan_text("alpha\nalpha\n", "python", rules=rules_arg)

    assert rules_arg == snapshot, (
        f"caller 가 넘긴 rules list 는 mutate 되면 안 된다, before={snapshot}, "
        f"after={rules_arg}"
    )


def test_caller_owned_rule_dict_is_not_mutated():
    rule = _custom_rule(
        id="HR-TEST-NOMUT",
        patterns=[r"alpha", r"beta"],
        match_mode="all",
    )
    rule_snapshot = copy.deepcopy(rule)
    patterns_id_before = id(rule["patterns"])

    heuristic_runner.scan_text("alpha and beta\n", "python", rules=[rule])

    assert rule == rule_snapshot, (
        f"caller 가 넘긴 rule dict 는 mutate 되면 안 된다, before={rule_snapshot}, "
        f"after={rule}"
    )
    assert id(rule["patterns"]) == patterns_id_before, (
        "patterns 리스트가 새 객체로 교체되어 있으면 안 된다 (in-place mutate 회피)"
    )


def test_default_quick_scan_rules_are_not_mutated_after_scan():
    before = copy.deepcopy(quick_scan_module.QUICK_SCAN_RULES)
    heuristic_runner.scan_text("import hashlib\nhashlib.md5(b'x')\n", "python")
    after = quick_scan_module.QUICK_SCAN_RULES
    assert after == before, "production QUICK_SCAN_RULES 는 mutate 되면 안 된다"


# ============================================================
# Test 8 — caller 0: production 경로 어디에서도 import 되지 않는다.
# ============================================================

_PRODUCTION_GUARD_FILES = (
    "analyzer/quick_scan.py",
    "analyzer/pipeline.py",
    "analyzer/semgrep_runner.py",
)
_PRODUCTION_GUARD_ROOTS = ("api", "agent", "validator", "db", "dashboard")


def test_heuristic_runner_not_imported_in_analyzer_core_modules():
    for relpath in _PRODUCTION_GUARD_FILES:
        path = _REPO_ROOT / relpath
        text = path.read_text(encoding="utf-8")
        assert "heuristic_runner" not in text, (
            f"{relpath} 가 heuristic_runner 를 참조한다 (caller 0 위반)"
        )


def test_heuristic_runner_not_imported_in_api_agent_validator_db_dashboard():
    for root in _PRODUCTION_GUARD_ROOTS:
        root_dir = _REPO_ROOT / root
        if not root_dir.exists():
            continue
        for py in root_dir.rglob("*.py"):
            text = py.read_text(encoding="utf-8")
            assert "heuristic_runner" not in text, (
                f"{py.relative_to(_REPO_ROOT)} 가 heuristic_runner 를 참조한다 "
                "(caller 0 위반)"
            )


# ============================================================
# Test 9 — 정적 purity guard: heuristic_runner.py 소스에 금지 패턴 없음.
# ============================================================

_FORBIDDEN_TOKENS = (
    "open(",
    "os.walk",
    "subprocess",
    "requests",
    "time.",
    "datetime",
    "FastAPI",
    "api.server",
    "DALLO_",
    "os.environ",
    "eval(",
    "exec(",
    "pickle.loads",
    "shell=True",
)


def test_heuristic_runner_source_has_no_forbidden_tokens():
    src = (_REPO_ROOT / "analyzer" / "heuristic_runner.py").read_text(encoding="utf-8")
    for bad in _FORBIDDEN_TOKENS:
        assert bad not in src, (
            f"analyzer/heuristic_runner.py 는 '{bad}' 를 포함하면 안 된다 "
            "(I/O/네트워크/시간/시스템 의존성 차단)"
        )


# ============================================================
# Test 10 — shared/schemas.py 가 heuristic_runner 를 알지 못한다 (계약 동결)
# ============================================================

def test_shared_schemas_does_not_reference_heuristic_runner():
    src = (_REPO_ROOT / "shared" / "schemas.py").read_text(encoding="utf-8")
    assert "heuristic_runner" not in src, (
        "shared/schemas.py 가 heuristic_runner 를 참조한다 — 본 wave 의 "
        "계약 동결 원칙(shared/schemas.py 변경 0건)을 위반한다"
    )
