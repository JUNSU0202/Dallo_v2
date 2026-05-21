"""Red/Blue 도메인 enrichment 모듈 (shared/red_blue.py).

순수 dict / list 도메인 헬퍼. 본 모듈은 분석 결과(취약점 dict)와 패치 결과
(패치 dict)에 공격(Red Team) / 방어(Blue Team) 컨텍스트를 파생해서 부착한다.

설계 원칙
---------
- ``shared`` 레이어 안쪽이므로 FastAPI / DB / settings / time / file system /
  subprocess / network 의존성을 갖지 않는다.
- ``analyzer`` / ``api`` / ``db`` / ``agent`` / ``reports`` / ``validator`` /
  ``dashboard`` 같은 application 레이어 모듈을 import 하지 않는다.
- 모든 ``enrich_*`` 함수는 입력 dict 를 변형하지 않는다 (``copy.deepcopy``).
- 반복 호출은 멱등하다: ``enrich(enrich(x)) == enrich(x)``. caller 가
  이미 채워 둔 Red/Blue 키는 ``setdefault`` 의미론으로 절대 덮어쓰지 않는다.
- ``shared/schemas.py`` 의 dataclass 필드는 본 모듈이 변경하지 않는다.
  본 모듈은 dict 표현 위에서만 enrichment 를 수행한다.
- 임포트 시점에 부수효과 0. 출력 dict 의 값은 plain JSON 호환 타입만 사용한다.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Optional


# ============================================================
# 알려진 CWE 별 공격 / 방어 템플릿 (도메인 사전).
# 외부 의존성 0. 모듈 임포트 시점에 단 한 번 초기화된다.
# ============================================================

_ATTACK_TEMPLATES: dict[str, dict[str, str]] = {
    "CWE-89": {
        "vector": "SQL injection",
        "scenario": (
            "An attacker may inject crafted input into a database query and "
            "read, modify, or delete records."
        ),
        "impact": "data exposure or unauthorized data manipulation",
        "defense": (
            "Use parameterized queries or ORM-bound values and reject unsafe "
            "query construction."
        ),
        "controlled_input": (
            "request parameter or user-controlled value used in query construction"
        ),
        "vulnerable_action": "dynamic SQL execution",
        "attack_goal": "read, modify, or delete unauthorized database records",
    },
    "CWE-78": {
        "vector": "command injection",
        "scenario": (
            "An attacker may pass shell metacharacters through user-controlled "
            "input and execute unintended commands."
        ),
        "impact": "remote command execution or host compromise",
        "defense": (
            "Avoid shell execution, pass arguments as arrays, and validate "
            "input against an allowlist."
        ),
        "controlled_input": (
            "request parameter or user-controlled value passed to a shell command"
        ),
        "vulnerable_action": "command execution",
        "attack_goal": "execute unintended operating system commands",
    },
    "CWE-79": {
        "vector": "cross-site scripting",
        "scenario": (
            "An attacker may inject script into a response rendered by another "
            "user's browser."
        ),
        "impact": "session theft, account actions, or client-side data exposure",
        "defense": (
            "Escape output, sanitize HTML, and use framework-safe rendering "
            "primitives."
        ),
        "controlled_input": "user-controlled text rendered into HTML",
        "vulnerable_action": "unsafe HTML/script rendering",
        "attack_goal": "execute script in another user's browser",
    },
    "CWE-798": {
        "vector": "hardcoded secret exposure",
        "scenario": (
            "An attacker who gains source access may reuse embedded "
            "credentials against external systems."
        ),
        "impact": "credential leakage and lateral movement",
        "defense": (
            "Move secrets to environment variables or a secret manager and "
            "rotate exposed values."
        ),
        "controlled_input": "source code or artifact access",
        "vulnerable_action": "secret reuse from code",
        "attack_goal": "reuse exposed credentials",
    },
    "CWE-328": {
        "vector": "weak cryptography",
        "scenario": (
            "An attacker may brute-force or collide weak hashes used for "
            "security-sensitive values."
        ),
        "impact": "password or token recovery",
        "defense": (
            "Use modern password hashing or SHA-256+ only where cryptographic "
            "hashes are appropriate."
        ),
        "controlled_input": "hashable secret or token material",
        "vulnerable_action": "weak digest generation",
        "attack_goal": "recover or collide sensitive values",
    },
    "CWE-502": {
        "vector": "unsafe deserialization",
        "scenario": (
            "An attacker may submit crafted serialized data that triggers "
            "code execution or object injection."
        ),
        "impact": "remote code execution or privilege abuse",
        "defense": (
            "Avoid unsafe deserializers for untrusted input and use strict "
            "schema validation."
        ),
        "controlled_input": "serialized payload",
        "vulnerable_action": "unsafe object deserialization",
        "attack_goal": "trigger object injection or code execution",
    },
    "CWE-22": {
        "vector": "path traversal",
        "scenario": (
            "An attacker may manipulate file paths to read or overwrite "
            "files outside the intended directory."
        ),
        "impact": "sensitive file disclosure or arbitrary file write",
        "defense": (
            "Normalize paths, enforce base-directory containment, and reject "
            "traversal sequences."
        ),
        "controlled_input": "file path segment",
        "vulnerable_action": "filesystem access",
        "attack_goal": "read or write files outside the intended directory",
    },
    "CWE-288": {
        "vector": "authentication bypass",
        "scenario": (
            "An attacker may control an account identifier or alternate "
            "verification path and mark another account as verified."
        ),
        "impact": "unauthorized account verification or access",
        "defense": (
            "Use the authenticated server-side principal, bind verification "
            "to the session owner, and reject request-controlled account "
            "identity."
        ),
        "controlled_input": "request-controlled account identifier",
        "vulnerable_action": "server-side verification state update",
        "attack_goal": "bypass account verification for another user",
    },
}

_GENERIC_DEFENSE_FALLBACK = (
    "Generate a secure refactoring and validate it with syntax and security checks."
)

_BEST_PATCH_PRIORITY: dict[str, int] = {
    "validated_defense": 0,
    "drafted_defense": 1,
    "needs_review": 2,
    "not_generated": 3,
}


# ============================================================
# Public API
# ============================================================


def enrich_vulnerability(vuln: dict) -> dict:
    """Return a vulnerability dict with Red Team enrichment fields attached.

    Adds the documented Red/Blue keys (``red_team_phase``, ``attack_vector``,
    ``attack_scenario``, ``security_impact``, ``blue_team_strategy``,
    ``exploitability``, ``attack_plan``) using ``setdefault`` semantics —
    caller-provided values are preserved. The input dict is never mutated.
    """
    item = deepcopy(vuln)
    template = _template_for(item)
    risk = (item.get("risk_level") or item.get("severity") or "unknown").lower()

    item.setdefault("red_team_phase", "attack_surface_mapping")
    item.setdefault("attack_vector", template["vector"])
    item.setdefault("attack_scenario", template["scenario"])
    item.setdefault("security_impact", template["impact"])
    item.setdefault("blue_team_strategy", template["defense"])
    item.setdefault("exploitability", _exploitability(risk, item.get("confidence", "")))
    item.setdefault("attack_plan", _build_attack_plan(item, template))
    return item


def enrich_patch(patch: dict, vuln: Optional[dict] = None) -> dict:
    """Return a patch dict with Blue Team enrichment fields attached.

    Adds ``blue_team_phase``, ``defense_strategy``, ``defense_outcome``,
    ``residual_risk``, ``defense_plan``. Empty-string / empty-dict values
    are treated as missing — ``PatchSuggestion.to_dict()`` ships these
    keys pre-populated with ``""`` defaults, and ``dict.setdefault`` would
    not fill them. Caller-provided non-empty values are preserved.
    The input dict is never mutated.
    """
    item = deepcopy(patch)
    vuln_safe = vuln if vuln is not None else {}

    sec = item.get("security_revalidation") or {}
    status_norm = _normalize_status(item.get("status"))

    outcome = _defense_outcome(item, sec, status_norm)

    if not item.get("blue_team_phase"):
        item["blue_team_phase"] = "remediation"
    if not item.get("defense_strategy"):
        item["defense_strategy"] = (
            vuln_safe.get("blue_team_strategy") or _GENERIC_DEFENSE_FALLBACK
        )
    if not item.get("defense_outcome"):
        item["defense_outcome"] = outcome
    if not item.get("residual_risk"):
        item["residual_risk"] = _residual_risk(item["defense_outcome"], sec)
    if not item.get("defense_plan"):
        item["defense_plan"] = _build_defense_plan(
            item, vuln_safe, item["defense_outcome"]
        )
    return item


def build_red_blue_summary(
    vulnerabilities: list[dict],
    patches: list[dict],
    *,
    include_attack_paths: bool = False,
) -> dict:
    """Build a compact Red/Blue posture summary for API and reports.

    Default top-level keys: ``red_team``, ``blue_team``, ``comparison``.
    When ``include_attack_paths`` is True, an additional ``attack_paths``
    key is appended. No other top-level marker keys (``mode``,
    ``system_label``, ``analysis_mode``) are emitted in this wave.
    """
    enriched_vulns = [enrich_vulnerability(v) for v in vulnerabilities]
    vuln_index: dict[str, dict] = {}
    for v in enriched_vulns:
        vid = v.get("id") or ""
        if vid:
            vuln_index[vid] = v

    enriched_patches: list[dict] = []
    for p in patches:
        pvid = p.get("vulnerability_id") or ""
        matching_vuln = vuln_index.get(pvid) if pvid else None
        enriched_patches.append(enrich_patch(p, matching_vuln))

    red_team = {
        "total_findings": len(enriched_vulns),
        "critical_or_high": sum(
            1
            for v in enriched_vulns
            if (v.get("risk_level") or v.get("severity") or "").lower()
            in ("critical", "high")
        ),
        "unique_cwe": len(
            {v.get("cwe_id") for v in enriched_vulns if v.get("cwe_id")}
        ),
        "affected_files": len(
            {v.get("file_path") for v in enriched_vulns if v.get("file_path")}
        ),
    }
    blue_team = {
        "patches_generated": sum(1 for p in enriched_patches if p.get("fixed_code")),
        "patches_verified": sum(
            1
            for p in enriched_patches
            if p.get("defense_outcome") == "validated_defense"
        ),
        "patches_needing_review": sum(
            1
            for p in enriched_patches
            if p.get("defense_outcome") == "needs_review"
        ),
    }
    comparison = build_defense_comparison(enriched_vulns, enriched_patches)

    summary: dict = {
        "red_team": red_team,
        "blue_team": blue_team,
        "comparison": comparison,
    }
    if include_attack_paths:
        summary["attack_paths"] = build_attack_paths(enriched_vulns, enriched_patches)
    return summary


def build_attack_paths(
    vulnerabilities: list[dict],
    patches: Optional[list[dict]] = None,
) -> list[dict]:
    """Build a list of Red/Blue attack-path rows.

    When ``patches`` is ``None`` or empty every row reports ``status="OPEN"``
    and ``residual_risk="high"``, with the defense text falling back to the
    vulnerability blue-team strategy (or a generic fallback). When a
    matching patch exists, status and residual risk are derived from the
    patch's enriched defense plan. Among multiple candidate patches the
    priority order is ``validated_defense < drafted_defense < needs_review
    < not_generated``.

    Empty ``id`` / ``vulnerability_id`` are intentionally not used as
    matching keys — a data-quality defect (missing id) must not surface as
    a fake defense success via empty-string collisions.
    """
    patch_map: dict[str, list[dict]] = {}
    for patch in patches or []:
        vid = patch.get("vulnerability_id") or ""
        if not vid:
            continue
        patch_map.setdefault(vid, []).append(patch)

    rows: list[dict] = []
    for vuln in vulnerabilities:
        template = _template_for(vuln)
        attack_plan = vuln.get("attack_plan") or _build_attack_plan(vuln, template)

        vid = vuln.get("id") or ""
        related = patch_map.get(vid, []) if vid else []
        best = _best_patch(related)

        if best is None:
            status = "OPEN"
            defense_text = vuln.get("blue_team_strategy") or _GENERIC_DEFENSE_FALLBACK
            residual = "high"
        else:
            enriched_best = best if best.get("defense_plan") else enrich_patch(best, vuln)
            plan = enriched_best.get("defense_plan") or {}
            status = plan.get("status", "OPEN")
            defense_text = (
                plan.get("strategy")
                or vuln.get("blue_team_strategy")
                or _GENERIC_DEFENSE_FALLBACK
            )
            residual = plan.get("residual_risk") or "high"

        rows.append(
            {
                "finding_id": vuln.get("id", ""),
                "rule_id": vuln.get("rule_id", ""),
                "title": vuln.get("title", ""),
                "cwe_id": vuln.get("cwe_id"),
                "file_path": vuln.get("file_path", ""),
                "line_number": vuln.get("line_number", 0),
                "attack_path": attack_plan.get("attack_path", ""),
                "attack_goal": attack_plan.get("attack_goal", ""),
                "status": status,
                "defense": defense_text,
                "residual_risk": residual,
            }
        )

    return rows


def build_defense_comparison(
    vulnerabilities: list[dict],
    patches: list[dict],
) -> dict:
    """Compute before/after Red/Blue posture arithmetic.

    Rules:
    - ``risk_reduction_percent`` is a float rounded to 1 decimal.
    - When ``before_total == 0`` the percent is ``0.0``.
    - ``removed`` (and therefore ``fixed_count``) is clamped to
      ``before_total`` so over-removal never produces negative totals.
    - ``introduced_count`` is summed from ``security_revalidation`` blocks
      and added to ``after_total``.
    """
    before_total = len(vulnerabilities)
    removed = 0
    introduced = 0

    for patch in patches:
        sec = patch.get("security_revalidation") or {}
        if sec:
            removed_count = int(sec.get("removed_count") or 0)
            # Tool comparison may miss the fixed finding when patched line
            # numbers shift. If revalidation passed and a real fix exists,
            # count at least 1 to prevent verified patches from reporting
            # 0% risk reduction.
            if sec.get("passed") and removed_count == 0 and patch.get("fixed_code"):
                removed_count = 1
            removed += removed_count
            introduced += int(sec.get("introduced_count") or 0)
        elif patch.get("defense_outcome") == "validated_defense":
            removed += 1

    removed = min(removed, before_total)
    after_total = max(before_total - removed + introduced, 0)
    if before_total:
        risk_reduction_percent = round((removed / before_total) * 100, 1)
    else:
        risk_reduction_percent = 0.0

    return {
        "before_total": before_total,
        "after_total": after_total,
        "fixed_count": removed,
        "remaining_count": max(before_total - removed, 0),
        "introduced_count": introduced,
        "risk_reduction_percent": risk_reduction_percent,
    }


# ============================================================
# Private helpers (not exported).
# ============================================================


def _template_for(vuln: dict) -> dict:
    cwe_id = vuln.get("cwe_id") or ""
    return _ATTACK_TEMPLATES.get(cwe_id) or _generic_template(vuln)


def _build_attack_plan(vuln: dict, template: dict) -> dict:
    entry_point = _entry_point(vuln)
    controlled_input = _controlled_input(vuln, template)
    vulnerable_action = template.get("vulnerable_action", "security-sensitive operation")
    impact = template.get("impact", "")

    return {
        "finding_id": vuln.get("id", ""),
        "attack_goal": (
            template.get("attack_goal") or impact or "abuse the vulnerable behavior"
        ),
        "entry_point": entry_point,
        "controlled_input": controlled_input,
        "trust_boundary": _trust_boundary(vuln, controlled_input),
        "vulnerable_action": vulnerable_action,
        "exploit_steps": [
            f"Reach {entry_point}.",
            f"Control {controlled_input}.",
            f"Trigger {vulnerable_action}.",
            f"Achieve {impact or 'security impact'}.",
        ],
        "impact": impact,
        "evidence": _evidence(vuln),
        "attack_path": f"{controlled_input} -> {vulnerable_action}",
    }


def _build_defense_plan(patch: dict, vuln: dict, outcome: str) -> dict:
    strategy = (
        patch.get("defense_strategy")
        or vuln.get("blue_team_strategy")
        or "Apply a focused secure refactor."
    )

    attack_plan = vuln.get("attack_plan") if vuln else None
    if not attack_plan and vuln:
        attack_plan = _build_attack_plan(vuln, _template_for(vuln))
    blocked_path = attack_plan.get("attack_path", "") if attack_plan else ""

    finding_id = patch.get("vulnerability_id") or (vuln.get("id", "") if vuln else "")

    return {
        "finding_id": finding_id,
        "status": _defense_status(outcome),
        "defense_goal": _defense_goal(vuln or {}),
        "strategy": strategy,
        "code_change": _code_change_summary(patch),
        "validation": _validation_steps(patch),
        "residual_risk": (
            patch.get("residual_risk")
            or _residual_risk(outcome, patch.get("security_revalidation") or {})
        ),
        "blocked_attack_path": blocked_path,
    }


def _generic_template(vuln: dict) -> dict:
    title = (vuln.get("title") or vuln.get("rule_id") or "security weakness").lower()
    return {
        "vector": title,
        "scenario": (
            "An attacker may abuse this weakness depending on reachability, "
            "input control, and deployed context."
        ),
        "impact": "increased application security risk",
        "defense": (
            "Apply a minimal secure refactor, validate behavior, and rescan "
            "the changed code."
        ),
        "controlled_input": "user-controlled input",
        "vulnerable_action": "security-sensitive operation",
        "attack_goal": "abuse the vulnerable behavior",
    }


def _exploitability(risk: str, confidence: str) -> str:
    conf = (confidence or "").upper()
    if risk in ("critical", "high") and conf != "LOW":
        return "high"
    if risk in ("medium", "high"):
        return "medium"
    return "low"


def _normalize_status(raw) -> str:
    if not isinstance(raw, str):
        return ""
    return raw.replace("PatchStatus.", "").lower()


def _defense_outcome(patch: dict, sec: dict, status: str) -> str:
    if sec.get("passed") or status == "verified":
        return "validated_defense"
    if status == "failed" or int(sec.get("introduced_count") or 0) > 0:
        return "needs_review"
    if patch.get("fixed_code"):
        return "drafted_defense"
    return "not_generated"


def _residual_risk(outcome: str, sec: dict) -> str:
    if outcome == "validated_defense":
        return "low"
    if int(sec.get("introduced_count") or 0) > 0:
        return "high"
    if outcome == "drafted_defense":
        return "medium"
    return "unknown"


def _defense_status(outcome: str) -> str:
    if outcome == "validated_defense":
        return "BLOCKED"
    if outcome == "drafted_defense":
        return "MITIGATING"
    if outcome == "needs_review":
        return "REVIEW"
    return "OPEN"


def _best_patch(patches: list[dict]) -> Optional[dict]:
    if not patches:
        return None

    def _outcome_of(p: dict) -> str:
        existing = p.get("defense_outcome")
        if isinstance(existing, str) and existing:
            return existing
        sec = p.get("security_revalidation") or {}
        status = _normalize_status(p.get("status"))
        return _defense_outcome(p, sec, status)

    return sorted(
        patches,
        key=lambda p: _BEST_PATCH_PRIORITY.get(_outcome_of(p), 9),
    )[0]


def _evidence(vuln: dict) -> str:
    code = (vuln.get("code_snippet") or vuln.get("function_code") or "").strip()
    if not code:
        return f"{vuln.get('file_path', '')}:{vuln.get('line_number', '')}"
    first = code.splitlines()[0].strip()
    return first[:180]


def _entry_point(vuln: dict) -> str:
    text = "\n".join(
        [
            vuln.get("function_code") or "",
            vuln.get("code_snippet") or "",
            vuln.get("description") or "",
        ]
    )
    for marker in ("@PostMapping", "@GetMapping", "@RequestMapping"):
        idx = text.find(marker)
        if idx >= 0:
            line = text[idx:].splitlines()[0].strip()
            return line[:120]
    return f"{vuln.get('file_path', 'unknown')}:{vuln.get('line_number', 0)}"


def _controlled_input(vuln: dict, template: dict) -> str:
    text = "\n".join([vuln.get("function_code") or "", vuln.get("code_snippet") or ""])
    if "@RequestParam String userId" in text:
        return "HTTP request parameter userId"
    if "req.query" in text:
        return "HTTP query parameter"
    if "request" in text.lower():
        return "HTTP request input"
    return template.get("controlled_input", "user-controlled input")


def _trust_boundary(vuln: dict, controlled_input: str) -> str:
    if "HTTP" in controlled_input:
        return "HTTP request -> server-side authorization/session state"
    cwe = vuln.get("cwe_id")
    if cwe == "CWE-89":
        return "application input -> database query"
    if cwe == "CWE-78":
        return "application input -> operating system command"
    return "untrusted input -> trusted operation"


def _defense_goal(vuln: dict) -> str:
    cwe = vuln.get("cwe_id")
    if cwe == "CWE-288":
        return "Remove request-controlled identity from account verification."
    if cwe == "CWE-89":
        return "Prevent user input from changing SQL query structure."
    if cwe == "CWE-78":
        return "Prevent user input from controlling command execution."
    label = vuln.get("attack_vector") or vuln.get("title") or "the attack path"
    return f"Block {label}."


def _code_change_summary(patch: dict) -> str:
    if not patch.get("fixed_code"):
        return "No code change generated yet."
    fix_type = patch.get("fix_type") or "recommended"
    return f"{fix_type} secure refactor generated by LLM."


def _validation_steps(patch: dict) -> list[str]:
    steps: list[str] = []
    syntax_valid = patch.get("syntax_valid")
    if syntax_valid is True:
        steps.append("syntax_check: passed")
    elif syntax_valid is False:
        steps.append("syntax_check: failed")
    else:
        steps.append("syntax_check: pending")

    sec = patch.get("security_revalidation") or {}
    if sec.get("passed") is True:
        steps.append("security_revalidation: passed")
    elif sec:
        steps.append("security_revalidation: needs_review")
    else:
        steps.append("security_revalidation: pending")
    return steps
