"""Celery 가용성 lazy detector 서비스 (api/services/celery_detector.py).

Wave 3-A: ``api/routers/analyze.py`` 가 들고 있던 Celery/Redis 가용성 감지
글로벌 상태(``_USE_CELERY``, ``_celery``, ``run_analysis_task``)와
``_ensure_celery_initialized()`` 본체를 HTTP 라우터 외부의 작은 서비스로
분리한 모듈.

설계 원칙:
  - FastAPI / api.server import 금지 — 라우터로부터 단방향 의존만 가진다.
  - ``api.celery_app`` / ``api.tasks`` import 와 Redis ping 은 모두
    함수 본체 안에서 lazy 하게 시도한다. 모듈 import 만으로 Celery/Redis
    부수효과가 일어나지 않게 한다.
  - 첫 호출 시 결과(``True`` / ``False``)를 모듈 글로벌에 캐시하여 후속
    호출에서는 추가 import / 네트워크 시도가 발생하지 않는다.
  - 테스트가 상태를 강제로 세팅 / 초기화 할 수 있도록 ``reset()``,
    ``set_state()`` 헬퍼를 제공한다.

라우터 호환:
  - ``api.routers.analyze`` 는 모듈 글로벌 ``_USE_CELERY`` / ``_celery`` /
    ``run_analysis_task`` 와 함수 ``_ensure_celery_initialized`` 표면을
    그대로 보존한다 (이전 wave 에서 테스트가 monkeypatch 하는 표면).
    라우터의 detector 는 본 서비스의 ``is_celery_available()`` 결과로
    자신의 모듈 글로벌을 동기화한다.
"""

from __future__ import annotations

from typing import Any

# 캐시된 가용성 (None = 아직 감지 안 함, True/False = 감지 결과)
_USE_CELERY: bool | None = None
# 첫 감지 성공 시 채워지는 Celery app / 태스크 핸들
_celery_app: Any = None
_run_analysis_task: Any = None


def is_celery_available() -> bool:
    """Celery/Redis 가용성을 lazy 하게 감지한다 (idempotent).

    캐시된 값(``_USE_CELERY``)이 ``None`` 이 아니면 그 값을 즉시 반환한다.
    그렇지 않은 경우에만 ``api.celery_app`` / ``api.tasks`` 임포트와 Redis
    ping 을 시도하고, 결과를 모듈 글로벌에 캐시한다.

    실패 사유(import 실패 / 네트워크 실패 / 임의의 예외) 는 모두 동일하게
    ``False`` 로 캐시한다 — 후속 요청에서 매번 재시도하지 않는다.
    """
    global _USE_CELERY, _celery_app, _run_analysis_task

    if _USE_CELERY is not None:
        return _USE_CELERY

    try:
        from api.celery_app import celery_app as _celery_local
        from api.tasks import run_analysis_task as _task_local
        _celery_local.connection_for_write().ensure_connection(
            max_retries=1, timeout=2,
        )
        _celery_app = _celery_local
        _run_analysis_task = _task_local
        _USE_CELERY = True
    except Exception:
        _USE_CELERY = False

    return _USE_CELERY


def get_celery_app() -> Any:
    """감지 성공 후 캐시된 Celery app 객체를 반환한다 (없으면 ``None``)."""
    return _celery_app


def get_run_analysis_task() -> Any:
    """감지 성공 후 캐시된 ``run_analysis_task`` 핸들을 반환한다 (없으면 ``None``)."""
    return _run_analysis_task


def reset() -> None:
    """캐시를 미초기화 상태(``None``) 로 되돌린다.

    테스트가 detector 의 fresh 상태를 재현하고 싶을 때 사용한다.
    """
    global _USE_CELERY, _celery_app, _run_analysis_task
    _USE_CELERY = None
    _celery_app = None
    _run_analysis_task = None


def set_state(
    *,
    use_celery: bool | None,
    celery_app: Any = None,
    run_task: Any = None,
) -> None:
    """detector 캐시를 강제로 세팅한다 (테스트 헬퍼).

    실제 Redis/Celery 없이 Celery 경로를 시뮬레이션 하거나, 강제로 비활성
    상태를 만들 때 사용한다.
    """
    global _USE_CELERY, _celery_app, _run_analysis_task
    _USE_CELERY = use_celery
    _celery_app = celery_app
    _run_analysis_task = run_task
