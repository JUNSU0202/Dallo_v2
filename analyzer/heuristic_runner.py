"""순수 heuristic fallback 스캐너 (analyzer/heuristic_runner.py).

Wave 5-H3: 정규식 기반 결정론적 heuristic 스캐너를 *별도* 헬퍼로 도입한다.
``analyzer.quick_scan.QUICK_SCAN_RULES`` 룰 집합을 재사용하지만 quick_scan 의
production 동작은 바꾸지 않는다. 본 wave 에서는 production caller 0 건 —
오직 tests 만 import 한다.

설계 원칙
---------
- 외부 I/O / 네트워크 / 시계 / 시스템 호출 없음. ``re`` 와 quick_scan 룰
  재사용만으로 결정론적으로 동작한다.
- 호출자가 넘긴 ``rules`` 리스트, 룰 dict, ``patterns`` 리스트를 어떤 형태로도
  mutate 하지 않는다 (caller-owned 입력 보존).
- finding shape (``rule_id`` / ``title`` / ``severity`` / ``cwe`` / ``line`` /
  ``code`` / ``message``) 는 quick_scan 과 1:1 동일하다.
- ``match_mode="all"`` / ``require_all=True`` 옵트인 정책은 Wave 5-H2 quick_scan
  policy seam 과 같은 의미를 가진다. all-mode 룰에 invalid regex 가 섞이면
  fail-closed (룰 전체 스킵). any-mode 룰의 invalid regex 는 조용히 스킵된다.
"""

from __future__ import annotations

import re

from analyzer.quick_scan import QUICK_SCAN_RULES


def _rule_requires_all(rule: dict) -> bool:
    """all-mode opt-in 판정 (Wave 5-H2 quick_scan 정책과 동일 의미)."""
    if rule.get("require_all") is True:
        return True
    mode = rule.get("match_mode")
    if isinstance(mode, str) and mode.lower() == "all":
        return True
    return False


def _make_finding(rule: dict, line_num: int, line_text: str) -> dict:
    return {
        "rule_id": rule["id"],
        "title": rule["title"],
        "severity": rule["severity"],
        "cwe": rule["cwe"],
        "line": line_num,
        "code": line_text.strip(),
        "message": rule["message"],
    }


def scan_text(code: str, language: str, rules: list | None = None) -> list:
    """결정론적 / 부수효과 없는 heuristic 스캔.

    Parameters
    ----------
    code : 스캔할 텍스트 (``\\n`` 기준 라인 분리).
    language : 룰의 ``languages`` 필드와 매칭되는 언어 식별자.
    rules : 명시되지 않으면 ``analyzer.quick_scan.QUICK_SCAN_RULES`` 를 그대로
        재사용한다. 호출자 소유 리스트와 그 안의 dict / patterns 리스트는
        mutate 되지 않는다.

    Returns
    -------
    list[dict]
        quick_scan 과 동일한 finding shape (line 기준 오름차순 정렬).
    """
    active_rules = QUICK_SCAN_RULES if rules is None else rules
    findings: list = []
    lines = code.split("\n")

    for rule in active_rules:
        if language not in rule.get("languages", ()):
            continue
        patterns = rule.get("patterns") or ()

        if _rule_requires_all(rule):
            # all-mode: 모든 패턴이 동일 라인에서 매치된 라인에만 finding.
            # 패턴 중 하나라도 invalid regex 이면 룰 전체 fail-closed.
            try:
                regexes = [re.compile(p, re.IGNORECASE) for p in patterns]
            except re.error:
                continue
            if not regexes:
                continue
            for line_num, line_text in enumerate(lines, 1):
                if all(rx.search(line_text) for rx in regexes):
                    findings.append(_make_finding(rule, line_num, line_text))
            continue

        # legacy any-mode: 한 패턴이라도 매치되면 finding, invalid regex 는 스킵.
        for pattern in patterns:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue
            for line_num, line_text in enumerate(lines, 1):
                if regex.search(line_text):
                    duplicate = any(
                        f["rule_id"] == rule["id"] and f["line"] == line_num
                        for f in findings
                    )
                    if not duplicate:
                        findings.append(_make_finding(rule, line_num, line_text))

    findings.sort(key=lambda f: f["line"])
    return findings
