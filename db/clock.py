"""DB 시계(clock) seam (Wave 4-P).

목적
----
SQLAlchemy 컬럼 default 가 ``datetime.utcnow`` 를 직접 참조하는 동안에는
Python 3.12+ 에서 매 INSERT 마다 ``DeprecationWarning`` 이 발생한다. 본
모듈은 그 책임을 한 곳으로 모아:

1. ``utcnow_naive()`` — ``datetime.now(timezone.utc).replace(tzinfo=None)``
   으로 deprecation-free 한 *naive UTC* datetime 을 만들어 컬럼 타입
   (``DateTime``, naive) 의 기존 동작을 보존한다.
2. ``now()`` — 모듈 레벨 fakeable ``_clock`` 콜러블에 위임해 테스트가 시간을
   고정할 수 있게 한다. 기본 콜러블은 ``utcnow_naive`` 라 운영 동작은 동일.
3. ``set_clock(fn)`` / ``reset_clock()`` — 테스트 전용 주입/복구 훅.

설계 노트
---------
- stdlib 의존만 사용한다. 다른 ``db.*`` / ``shared.*`` / 서드파티 모듈을
  import 하지 않아 임포트 사이클을 만들지 않는다.
- ``utcnow_naive`` 자체는 fake 의 영향을 받지 않는다. ``set_clock`` 으로
  주입된 가짜 시간은 ``now()`` 만 통과한다 — 시각의 *실측값* 을 직접
  필요로 하는 코드와, 테스트에서 시간을 고정하고 싶은 코드 간의 책임을
  분리하기 위함이다.
- API/시리얼라이즈 형태(naive datetime, ``isoformat()`` 의 ``+00:00`` 미부착)
  를 명시적으로 보존한다.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable


def utcnow_naive() -> datetime:
    """Deprecation-free 경로로 *naive UTC* datetime 을 반환한다.

    ``datetime.utcnow()`` 와 동일한 형태(``tzinfo is None``)지만 내부적으로는
    timezone-aware ``datetime.now(timezone.utc)`` 를 사용한 뒤 tzinfo 를
    벗겨 기존 컬럼 타입 호환성을 유지한다.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


_clock: Callable[[], datetime] = utcnow_naive


def now() -> datetime:
    """현재 시각을 반환한다 — 테스트가 ``set_clock`` 으로 고정 가능."""
    return _clock()


def set_clock(fn: Callable[[], datetime]) -> None:
    """테스트용: 시간 소스를 0-인자 콜러블로 교체한다."""
    global _clock
    _clock = fn


def reset_clock() -> None:
    """테스트용: 시간 소스를 기본(``utcnow_naive``) 으로 복구한다."""
    global _clock
    _clock = utcnow_naive
