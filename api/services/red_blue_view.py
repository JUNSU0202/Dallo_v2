"""Red/Blue 뷰 enrichment 서비스 (api/services/red_blue_view.py).

Wave 5-D: ``api/services/dashboard_queries.py`` 가 반환하는 read-only 응답
dict 의 끝단에 ``shared.red_blue.enrich_*`` 결과를 *추가만* 부착하기 위한
HTTP/Pydantic 비의존 헬퍼 모듈.

설계 원칙
---------
- FastAPI / Pydantic / ``api.server`` / DB / settings / env / filesystem /
  subprocess / network / time / LLM 의존이 0 이다.
- 입력 dict / list 는 절대 변형하지 않는다 (``shared.red_blue`` 의 deepcopy
  + setdefault 의미론을 그대로 노출).
- 비-list 입력(``None``, ``"x"``, ``{}``)은 빈 리스트로 정규화한다.
- ``enrich_stats`` 는 vulnerabilities/patches 중 하나라도 비어 있지 않을 때만
  ``red_blue_summary`` 키를 추가한다 — ``/api/stats`` 빈 응답의 정확한 6키
  계약을 깨면 안 된다.
- ``build_view_summary`` 는 항상 ``include_attack_paths=True`` 로 호출하여
  ``red_team`` / ``blue_team`` / ``comparison`` / ``attack_paths`` 4 키를 반환한다.
"""

from __future__ import annotations

from shared.red_blue import (
    build_red_blue_summary,
    enrich_patch,
    enrich_vulnerability,
)


def _as_list(value) -> list:
    """list 가 아닌 입력(None, str, dict 등)을 빈 리스트로 정규화한다."""
    return list(value) if isinstance(value, list) else []


def enrich_vulnerabilities(vulnerabilities) -> list[dict]:
    """취약점 리스트의 각 항목에 Red Team enrichment 키를 추가한 새 리스트 반환."""
    return [enrich_vulnerability(v) for v in _as_list(vulnerabilities) if isinstance(v, dict)]


def enrich_patches(patches, vulnerabilities=None) -> list[dict]:
    """패치 리스트의 각 항목에 Blue Team enrichment 키를 추가한 새 리스트 반환.

    ``vulnerabilities`` 가 주어지면 ``patch["vulnerability_id"]`` 와
    ``vuln["id"]`` 를 매칭하여 vuln 컨텍스트를 함께 전달한다. 빈 id 는
    매칭 키로 사용하지 않는다 (데이터 품질 결함이 가짜 매칭으로 나타나지
    않도록).

    ``shared.red_blue.build_red_blue_summary`` 와 동일한 의도로, 매칭에
    사용하는 vuln 은 먼저 enrich 한다. 그래야 ``enrich_patch`` 안의
    ``vuln_safe.get("blue_team_strategy")`` 가 CWE-derived 방어 문구를
    반환하고, patch ``defense_strategy`` 가 generic fallback 대신 해당
    CWE 의 구체적 방어 전략을 받는다.
    """
    enriched_vulns = enrich_vulnerabilities(vulnerabilities)
    vuln_index: dict[str, dict] = {}
    for v in enriched_vulns:
        vid = v.get("id") or ""
        if vid:
            vuln_index[vid] = v

    enriched: list[dict] = []
    for p in _as_list(patches):
        if not isinstance(p, dict):
            continue
        pvid = p.get("vulnerability_id") or ""
        match = vuln_index.get(pvid) if pvid else None
        enriched.append(enrich_patch(p, match))
    return enriched


def build_view_summary(vulnerabilities, patches) -> dict:
    """대시보드/세션 응답에 임베드 가능한 Red/Blue 요약 dict.

    항상 ``red_team`` / ``blue_team`` / ``comparison`` / ``attack_paths`` 4 키.
    비-list 입력은 빈 리스트로 정규화된다.
    """
    return build_red_blue_summary(
        _as_list(vulnerabilities),
        _as_list(patches),
        include_attack_paths=True,
    )


def enrich_stats(stats: dict, vulnerabilities=None, patches=None) -> dict:
    """``/api/stats`` 응답에 옵션으로 ``red_blue_summary`` 를 부착한 새 dict.

    ``vulnerabilities`` 와 ``patches`` 가 모두 비어 있으면 입력 stats 를
    그대로 (얕은 복사 후) 반환한다 — ``/api/stats`` 빈 응답의 정확한 6키
    셰이프 계약을 깨면 안 된다.
    """
    if not isinstance(stats, dict):
        return stats

    vulns = _as_list(vulnerabilities)
    patch_list = _as_list(patches)
    out = dict(stats)
    if not vulns and not patch_list:
        return out

    out["red_blue_summary"] = build_view_summary(vulns, patch_list)
    return out


def enrich_analysis_result(result):
    """세션 상세(``get_analysis_by_session``) 결과 dict 에 Red/Blue 부착.

    - 입력이 dict 가 아니거나 ``error`` 키가 있으면 그대로 반환한다.
    - ``vulnerabilities`` / ``patches`` 가 list 면 enrich 한 새 list 로 교체하고
      ``red_blue_summary`` 를 추가한다. raw list 가 둘 다 없으면 키만 보존한 채
      enrichment 키를 추가하지 않는다.
    """
    if not isinstance(result, dict):
        return result
    if "error" in result:
        return result

    raw_vulns = result.get("vulnerabilities")
    raw_patches = result.get("patches")
    has_vulns = isinstance(raw_vulns, list) and len(raw_vulns) > 0
    has_patches = isinstance(raw_patches, list) and len(raw_patches) > 0

    if not has_vulns and not has_patches:
        return dict(result)

    out = dict(result)
    enriched_vulns = enrich_vulnerabilities(raw_vulns)
    enriched_patches = enrich_patches(raw_patches, raw_vulns)
    out["vulnerabilities"] = enriched_vulns
    out["patches"] = enriched_patches
    out["red_blue_summary"] = build_view_summary(raw_vulns, raw_patches)
    return out


__all__ = [
    "enrich_vulnerabilities",
    "enrich_patches",
    "build_view_summary",
    "enrich_stats",
    "enrich_analysis_result",
]
