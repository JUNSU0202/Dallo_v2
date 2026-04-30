"""분석 잡 메모리 저장소 정리 헬퍼 (api/services/analysis_jobs_store.py).

Wave 3-D: ``api/routers/analyze.py`` 의 ``analysis_jobs: dict = {}`` 메모리
폴백이 무한 증가할 수 있는 위험을 줄이기 위해, TTL/캡 기반의 작은 정리
헬퍼를 분리한다. 라우터의 module-level dict 자체는 그대로 유지되어
기존 monkeypatch 패턴(``monkeypatch.setattr(analyze_router, 'analysis_jobs',
{})``)을 깨지 않는다.

설계 원칙:
  - FastAPI / api.server 를 import 하지 않는다 (서비스는 HTTP 계층 비의존).
  - 호출자가 소유한 mutable mapping 을 받아 in-place 로 정리한다 — 라우터의
    ``analysis_jobs`` 가 그대로 전달된다.
  - 잡 메타에 이미 존재하는 ``created_at`` ISO 문자열을 사용한다. 누락/말썽
    있는 timestamp 도 라우터를 깨뜨리지 않는다 (정리에서 안전하게 스킵).
  - 시계는 인자(``now``) 로 주입 가능 — 테스트가 결정적으로 만료를 검증한다.
  - 보수적인 기본값(캡 500, TTL 1시간) 을 갖되, 환경변수
    ``DALLO_ANALYSIS_JOBS_MAX`` / ``DALLO_ANALYSIS_JOBS_TTL_SECONDS`` 로 조정
    가능하다.
  - 호출자가 ``exclude_ids`` 로 보호 대상을 명시할 수 있어, 방금 만든 잡이나
    현재 조회 중인 잡이 예기치 않게 제거되지 않는다.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Iterable, MutableMapping, Optional


DEFAULT_MAX_JOBS = 500
DEFAULT_TTL_SECONDS = 60 * 60  # 1 hour


def _read_env_positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def get_default_max_jobs() -> int:
    """현재 프로세스의 기본 캡 (호출 시점에 환경변수 재확인)."""
    return _read_env_positive_int("DALLO_ANALYSIS_JOBS_MAX", DEFAULT_MAX_JOBS)


def get_default_ttl_seconds() -> int:
    """현재 프로세스의 기본 TTL (호출 시점에 환경변수 재확인)."""
    return _read_env_positive_int(
        "DALLO_ANALYSIS_JOBS_TTL_SECONDS", DEFAULT_TTL_SECONDS,
    )


def _parse_iso(value: object) -> Optional[datetime]:
    """``created_at`` ISO 문자열을 안전하게 파싱한다. 실패 시 ``None``."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def cleanup(
    jobs: MutableMapping[str, dict],
    *,
    max_size: Optional[int] = None,
    ttl_seconds: Optional[int] = None,
    now: Optional[datetime] = None,
    exclude_ids: Iterable[str] = (),
) -> int:
    """``jobs`` 를 in-place 로 정리하고 제거된 항목 수를 반환한다.

    동작:
      1. TTL 패스 — ``created_at`` 이 파싱 가능하고 ``now - created_at``
         이 ``ttl_seconds`` 를 초과하는 항목을 제거. 파싱 불가/누락 항목은
         TTL 로 제거하지 않는다 (안전).
      2. 캡 패스 — 정리 후에도 ``len(jobs) > max_size`` 이면 ``created_at``
         기준 오래된 순으로 초과분만 제거. 파싱 불가/누락 항목은 가장 새것으로
         취급되어 가장 늦게 제거된다.
      3. ``exclude_ids`` 에 속한 키는 어떤 패스에서도 제거하지 않는다.

    인자:
      - ``max_size`` / ``ttl_seconds``: ``None`` 이면 환경변수 기반 기본값.
        ``0`` 이하는 해당 패스를 비활성화한다.
      - ``now``: 시계 주입(테스트). ``None`` 이면 ``datetime.now()``.
      - ``exclude_ids``: 보호할 잡 ID 들 (방금 삽입할 잡, 조회 중인 잡 등).
    """
    if max_size is None:
        max_size = get_default_max_jobs()
    if ttl_seconds is None:
        ttl_seconds = get_default_ttl_seconds()
    if now is None:
        now = datetime.now()

    excluded = set(exclude_ids)
    removed = 0

    if ttl_seconds and ttl_seconds > 0:
        cutoff = now - timedelta(seconds=ttl_seconds)
        for job_id in list(jobs.keys()):
            if job_id in excluded:
                continue
            meta = jobs.get(job_id)
            ts = _parse_iso(
                meta.get("created_at") if isinstance(meta, dict) else None,
            )
            if ts is not None and ts < cutoff:
                jobs.pop(job_id, None)
                removed += 1

    if max_size and max_size > 0 and len(jobs) > max_size:
        sentinel = datetime.max

        def _age_key(item):
            _jid, meta = item
            ts = _parse_iso(
                meta.get("created_at") if isinstance(meta, dict) else None,
            )
            return ts or sentinel

        prunable = [
            (jid, meta) for jid, meta in jobs.items() if jid not in excluded
        ]
        prunable.sort(key=_age_key)

        excess = len(jobs) - max_size
        for jid, _meta in prunable:
            if excess <= 0:
                break
            jobs.pop(jid, None)
            removed += 1
            excess -= 1

    return removed


__all__ = [
    "DEFAULT_MAX_JOBS",
    "DEFAULT_TTL_SECONDS",
    "get_default_max_jobs",
    "get_default_ttl_seconds",
    "cleanup",
]
