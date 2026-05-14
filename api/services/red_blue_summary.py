"""Red/Blue 요약 서비스 (api/services/red_blue_summary.py).

Wave 5-C: ``shared.red_blue.build_red_blue_summary`` 순수 헬퍼를 API 라우터에서
직접 호출하지 않고, HTTP 비의존 서비스 계층 뒤에 두기 위한 모듈.

설계 원칙:
  - FastAPI / Pydantic / ``api.server`` 의존이 없다 (HTTP 비의존).
  - 데이터 소스 우선순위: DB ``get_latest_analysis`` → JSON
    ``load_full_result`` → 빈 셰이프(취약점/패치 0건). 두 소스가 모두
    실패해도 fail-closed 로 0건 빈 응답을 돌려주며 500 을 던지지 않는다.
  - 입력 정규화: 소스 dict 의 ``vulnerabilities`` / ``patches`` 가 list 가
    아니면 빈 리스트로 폴백 (None / "not-a-list" / dict 모두 안전).
  - ``include_attack_paths=True`` 가 기본값이며 응답의 top-level 키는 항상
    ``red_team``, ``blue_team``, ``comparison``, ``attack_paths`` 4개.
  - 데이터 소스 모듈은 모듈 레벨에서 import 하여 테스트가
    ``monkeypatch.setattr`` 로 fake 를 주입할 수 있게 한다.
"""

from __future__ import annotations

from typing import Optional

from api import result_sources
from db import service as db_service
from shared.red_blue import build_red_blue_summary


def _as_list(value) -> list:
    """list 가 아닌 값은 빈 리스트로 정규화한다."""
    return list(value) if isinstance(value, list) else []


def _load_source() -> Optional[dict]:
    """DB → JSON 순으로 분석 결과 dict 를 가져온다.

    각 소스의 예외는 격리해 다음 소스로 넘어간다. 모두 실패/부재면 ``None``.
    """
    try:
        latest = db_service.get_latest_analysis()
    except Exception:
        latest = None
    if isinstance(latest, dict) and latest:
        return latest

    try:
        full = result_sources.load_full_result()
    except Exception:
        full = None
    if isinstance(full, dict) and full:
        return full

    return None


def get_red_blue_summary(*, include_attack_paths: bool = True) -> dict:
    """Red/Blue 요약 dict 를 반환한다.

    반환 셰이프:
      - ``red_team`` (dict)
      - ``blue_team`` (dict)
      - ``comparison`` (dict)
      - ``attack_paths`` (list[dict]) — ``include_attack_paths=True`` 일 때.
    """
    source = _load_source() or {}
    vulnerabilities = _as_list(source.get("vulnerabilities"))
    patches = _as_list(source.get("patches"))
    return build_red_blue_summary(
        vulnerabilities,
        patches,
        include_attack_paths=include_attack_paths,
    )


__all__ = ["get_red_blue_summary"]
