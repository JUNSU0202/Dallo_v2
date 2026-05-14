"""LLM 입력 최적화 도메인 헬퍼 (shared/llm_optimization.py).

순수 모듈. LLM 에 보낼 ``VulnerabilityReport`` 후보를 스코프 필터링,
우선순위 정렬, 개수 cap, 그리고 컨텍스트 trim 까지 수행해 안전한 입력
세트를 만든다.

설계 원칙
---------
- ``shared`` 레이어이므로 FastAPI / DB / settings / time / file system /
  subprocess / network / agent / validator / dashboard 의존성을 갖지 않는다.
- 입력 객체는 ``copy.deepcopy`` 로 보호된다 — caller-owned 객체는 본 모듈이
  변경하지 않는다.
- 출력 ``summary`` 는 plain JSON 호환 타입만 사용해 API 응답에 그대로
  실릴 수 있도록 한다.
- 입력은 ``shared.schemas.VulnerabilityReport`` 또는 동일한 attribute set
  을 가진 임의 객체 (dataclass / 일반 클래스) 를 받는다 — 본 모듈은 객체의
  attribute 만 읽고 구체 타입에 의존하지 않는다.
- 임포트 시점에 부수효과 0. LLM 제공자 / 모델 식별자 / 라우팅 정책
  토큰은 본 wave 의 관심사가 아니며 도입하지 않는다.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Optional


# ============================================================
# Scope alias 사전.
# Gusle01 의 도메인 직관(예: SQLI -> CWE-89) 을 재현한다.
# ============================================================


SCOPE_ALIASES: dict[str, str] = {
    "SQLI": "CWE-89",
    "SQL_INJECTION": "CWE-89",
    "CMDI": "CWE-78",
    "COMMAND_INJECTION": "CWE-78",
    "XSS": "CWE-79",
    "AUTH_BYPASS": "CWE-288",
    "AUTHENTICATION_BYPASS": "CWE-288",
    "PATH_TRAVERSAL": "CWE-22",
    "HARDCODED_SECRET": "CWE-798",
}


# ============================================================
# 정렬 우선순위 사전.
# ============================================================


_RISK_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}

_UNKNOWN_RANK = 99


_CVE_SEARCH_FIELDS: tuple[str, ...] = (
    "cwe_id",
    "rule_id",
    "title",
    "description",
    "more_info",
    "code_snippet",
    "function_code",
)


_TRIM_FIELDS: tuple[str, ...] = (
    "function_code",
    "code_snippet",
    "file_imports",
)


# ============================================================
# Config.
# ============================================================


@dataclass
class LLMOptimizationConfig:
    """LLM 입력 최적화 정책.

    필드
    ----
    enabled
        False 이면 필터 / 정렬 / cap 을 모두 우회한다. (trim 과 deepcopy 는
        prompt 안정성을 위해 항상 적용된다.)
    cve_scope
        CVE 식별자 문자열 목록. 본 토큰이 vuln 의 텍스트 필드 어느 한 곳에
        포함되면 매칭된다.
    cwe_scope
        CWE 토큰 또는 alias 목록. ``SCOPE_ALIASES`` 로 정규화된 뒤
        ``vuln.cwe_id`` 와 비교한다.
    rule_scope
        분석기 rule id (대소문자 무시) 목록.
    max_targets
        선택할 vuln 개수 상한. ``<= 0`` 이면 cap 미적용.
    max_context_chars
        ``function_code`` / ``code_snippet`` / ``file_imports`` 의 글자수
        상한. ``<= 0`` 이면 trim 미적용.
    batch_enabled / batch_size
        본 wave 에서는 summary 에 그대로 보고만 한다 (후속 wave 에서
        배치 파이프라인이 참조).
    """

    enabled: bool = True
    cve_scope: list[str] = field(default_factory=list)
    cwe_scope: list[str] = field(default_factory=list)
    rule_scope: list[str] = field(default_factory=list)
    max_targets: int = 10
    max_context_chars: int = 2400
    batch_enabled: bool = True
    batch_size: int = 5


# ============================================================
# Public API.
# ============================================================


def trim_vulnerability_context(vulnerability, max_chars: int):
    """Return a deepcopy of ``vulnerability`` with long context fields trimmed.

    ``function_code`` / ``code_snippet`` / ``file_imports`` 중 ``max_chars``
    를 초과하는 필드는 head + 마커 + tail 형태로 축약한다.
    ``max_chars <= 0`` 이면 trim 을 수행하지 않는다 (단, deepcopy 는 항상
    적용된다).
    """
    out = deepcopy(vulnerability)
    if max_chars is None or max_chars <= 0:
        return out
    for attr in _TRIM_FIELDS:
        val = getattr(out, attr, None)
        if not isinstance(val, str):
            continue
        if len(val) <= max_chars:
            continue
        head_len = max_chars // 2
        tail_len = max_chars - head_len
        omitted = len(val) - max_chars
        marker = f"\n... [truncated {omitted} chars] ...\n"
        new_val = val[:head_len] + marker + val[-tail_len:]
        setattr(out, attr, new_val)
    return out


def scoped_copy(vulnerability, max_chars: int):
    """Public alias of :func:`trim_vulnerability_context`."""
    return trim_vulnerability_context(vulnerability, max_chars)


def optimize_llm_targets(
    vulnerabilities,
    config: Optional[LLMOptimizationConfig] = None,
):
    """Filter, sort, cap, and trim ``vulnerabilities`` for LLM consumption.

    Returns
    -------
    (targets, summary)
        ``targets`` 는 deepcopy 된 vuln 객체 목록 (원본 비파괴).
        ``summary`` 는 JSON 호환 dict 로 후속 API 응답에 그대로 실릴 수
        있다.
    """
    cfg = config if config is not None else LLMOptimizationConfig()
    input_list = list(vulnerabilities)
    input_count = len(input_list)

    cwe_resolved, aliases_used, cwe_had_meaningful = _resolve_cwe_scope(cfg.cwe_scope)
    rule_resolved, rule_had_meaningful = _resolve_rule_scope(cfg.rule_scope)
    cve_resolved, cve_had_meaningful = _resolve_cve_scope(cfg.cve_scope)

    if not cfg.enabled:
        targets = [
            trim_vulnerability_context(v, cfg.max_context_chars) for v in input_list
        ]
        summary = _build_summary(
            cfg,
            input_count=input_count,
            selected_count=len(targets),
            cap_applied=False,
            cwe_resolved=cwe_resolved,
            rule_resolved=rule_resolved,
            cve_resolved=cve_resolved,
            aliases_used=aliases_used,
        )
        return targets, summary

    # Safety: 사용자가 의미 있는 scope 토큰을 제공했지만 모든 카테고리에서
    # 정규화/해석 결과 매칭 가능한 항목이 하나도 남지 않은 경우 (예: 오타난
    # alias) 전체로 넓히지 않고 0 으로 좁힌다. 단, 한 카테고리라도 정상 해석
    # 되면 그 카테고리로 필터링하고 다른 카테고리의 알 수 없는 토큰은 무시한다
    # — 한쪽의 오타가 정상 scope 까지 무효화하지 않도록.
    has_meaningful_scope = (
        cwe_had_meaningful or rule_had_meaningful or cve_had_meaningful
    )
    has_resolved_scope = bool(cwe_resolved or rule_resolved or cve_resolved)
    narrow_to_zero = has_meaningful_scope and not has_resolved_scope

    if narrow_to_zero:
        filtered = []
    elif cwe_resolved or rule_resolved or cve_resolved:
        filtered = [
            v
            for v in input_list
            if _matches_scope(v, cwe_resolved, rule_resolved, cve_resolved)
        ]
    else:
        filtered = list(input_list)

    filtered.sort(key=_priority_key)

    cap_applied = False
    if cfg.max_targets > 0 and len(filtered) > cfg.max_targets:
        filtered = filtered[: cfg.max_targets]
        cap_applied = True

    targets = [
        trim_vulnerability_context(v, cfg.max_context_chars) for v in filtered
    ]

    summary = _build_summary(
        cfg,
        input_count=input_count,
        selected_count=len(targets),
        cap_applied=cap_applied,
        cwe_resolved=cwe_resolved,
        rule_resolved=rule_resolved,
        cve_resolved=cve_resolved,
        aliases_used=aliases_used,
    )
    return targets, summary


# ============================================================
# Private helpers.
# ============================================================


def _resolve_cwe_scope(scope_list) -> tuple[list[str], list[str], bool]:
    resolved: list[str] = []
    aliases_used: list[str] = []
    had_meaningful = False
    if not scope_list:
        return resolved, aliases_used, had_meaningful
    for token in scope_list:
        if not isinstance(token, str):
            continue
        stripped = token.strip()
        if not stripped:
            continue
        had_meaningful = True
        norm = stripped.upper().replace(" ", "_").replace("-", "_")
        if norm in SCOPE_ALIASES:
            cwe = SCOPE_ALIASES[norm]
            if cwe not in resolved:
                resolved.append(cwe)
            if norm not in aliases_used:
                aliases_used.append(norm)
            continue
        # 직접 CWE 토큰. "CWE_89" 또는 "CWE-89" 또는 "89".
        direct = stripped.upper()
        if direct.startswith("CWE-"):
            if direct not in resolved:
                resolved.append(direct)
        elif direct.startswith("CWE_"):
            cwe = "CWE-" + direct[4:]
            if cwe not in resolved:
                resolved.append(cwe)
        elif direct.isdigit():
            cwe = f"CWE-{direct}"
            if cwe not in resolved:
                resolved.append(cwe)
    return resolved, aliases_used, had_meaningful


def _resolve_rule_scope(scope_list) -> tuple[list[str], bool]:
    resolved: list[str] = []
    had_meaningful = False
    if not scope_list:
        return resolved, had_meaningful
    for token in scope_list:
        if not isinstance(token, str):
            continue
        norm = token.strip().upper()
        if not norm:
            continue
        had_meaningful = True
        if norm not in resolved:
            resolved.append(norm)
    return resolved, had_meaningful


def _resolve_cve_scope(scope_list) -> tuple[list[str], bool]:
    resolved: list[str] = []
    had_meaningful = False
    if not scope_list:
        return resolved, had_meaningful
    for token in scope_list:
        if not isinstance(token, str):
            continue
        norm = token.strip().upper()
        if not norm:
            continue
        had_meaningful = True
        if norm not in resolved:
            resolved.append(norm)
    return resolved, had_meaningful


def _matches_scope(
    vuln,
    cwe_resolved: list[str],
    rule_resolved: list[str],
    cve_resolved: list[str],
) -> bool:
    if cwe_resolved:
        vcwe = getattr(vuln, "cwe_id", None)
        if isinstance(vcwe, str) and vcwe.strip().upper() in cwe_resolved:
            return True
    if rule_resolved:
        vrule = getattr(vuln, "rule_id", None)
        if isinstance(vrule, str) and vrule.strip().upper() in rule_resolved:
            return True
    if cve_resolved:
        for cve in cve_resolved:
            for field_name in _CVE_SEARCH_FIELDS:
                val = getattr(vuln, field_name, "")
                if isinstance(val, str) and cve in val.upper():
                    return True
    return False


def _priority_key(vuln) -> tuple:
    risk_raw = getattr(vuln, "risk_level", "") or ""
    risk = risk_raw.lower() if isinstance(risk_raw, str) else ""

    sev_raw = getattr(vuln, "severity", "") or ""
    severity = sev_raw.upper() if isinstance(sev_raw, str) else ""

    cvss_raw = getattr(vuln, "cvss_score", 0.0)
    try:
        cvss_val = float(cvss_raw) if cvss_raw is not None else 0.0
    except (TypeError, ValueError):
        cvss_val = 0.0

    file_path = getattr(vuln, "file_path", "") or ""
    if not isinstance(file_path, str):
        file_path = ""

    line_raw = getattr(vuln, "line_number", 0)
    try:
        line_val = int(line_raw) if line_raw is not None else 0
    except (TypeError, ValueError):
        line_val = 0

    return (
        _RISK_ORDER.get(risk, _UNKNOWN_RANK),
        _SEVERITY_ORDER.get(severity, _UNKNOWN_RANK),
        -cvss_val,
        file_path,
        line_val,
    )


def _build_summary(
    cfg: LLMOptimizationConfig,
    *,
    input_count: int,
    selected_count: int,
    cap_applied: bool,
    cwe_resolved: list[str],
    rule_resolved: list[str],
    cve_resolved: list[str],
    aliases_used: list[str],
) -> dict:
    return {
        "enabled": bool(cfg.enabled),
        "input_count": int(input_count),
        "selected_count": int(selected_count),
        "cap_applied": bool(cap_applied),
        "max_targets": int(cfg.max_targets),
        "max_context_chars": int(cfg.max_context_chars),
        "batch_enabled": bool(cfg.batch_enabled),
        "batch_size": int(cfg.batch_size),
        "scope": {
            "cve": list(cve_resolved),
            "cwe": list(cwe_resolved),
            "rule": list(rule_resolved),
            "aliases_used": list(aliases_used),
        },
    }
