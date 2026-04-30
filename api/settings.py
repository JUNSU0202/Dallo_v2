"""애플리케이션 부트스트랩 설정 (api/settings.py).

Wave 2-H: api/server.py 와 api/routers/* 에 흩어져 있던 경로/CORS 기본값을
한 곳으로 모은 단일 소스 오브 트루스. FastAPI/DB/Celery 의존성을 갖지 않으며,
임포트만으로 디렉터리 생성 같은 부수효과를 일으키지 않는다.

Wave 3-C: 경로 설정 안정화.
  - ``UPLOAD_DIR`` / ``REPORTS_DIR`` 의 기본값을 repo root 기준 absolute
    path 로 통일하여 cwd (현재 작업 디렉터리) 의존을 제거한다.
  - 환경변수에 절대 경로가 들어오면 그대로 사용하고, 상대 경로가 들어오면
    cwd 가 아니라 ``PROJECT_ROOT`` 에 join 하여 절대 경로로 정규화한다.

기본값은 기능 측면에서는 기존과 동일하지만 (uploads/, reports/), 절대 경로로
표현되어 어떤 cwd 에서 서버를 띄워도 동일한 디렉터리를 가리킨다.

오버라이드 가능한 환경변수:
  - ``DALLO_UPLOAD_DIR`` : 업로드/패치 적용 디렉터리 (기본 ``<root>/uploads``)
  - ``DALLO_REPORTS_DIR`` : 리포트/풀 결과 출력 디렉터리 (기본 ``<root>/reports``)
  - ``DALLO_CORS_ORIGINS`` : 콤마 구분 origin 목록.
        기본 ``"http://localhost:3000,http://localhost:5173"``.
        값이 비어있거나 모두 공백이면 기본값으로 폴백한다.

``PROJECT_ROOT`` / ``DASHBOARD_DIR`` 는 파일 위치(``api/settings.py``) 기반
으로 계산되며 환경변수 오버라이드를 받지 않는다 (의도적으로 단순화).
"""

from __future__ import annotations

import os
from typing import List


PROJECT_ROOT: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD_DIR: str = os.path.join(PROJECT_ROOT, "dashboard", "dist")

_DEFAULT_CORS_ORIGINS: List[str] = [
    "http://localhost:3000",
    "http://localhost:5173",
]


def _parse_cors_origins(raw: str | None) -> List[str]:
    """콤마 구분 문자열을 origin 리스트로 파싱. 비어있으면 기본값으로 폴백."""
    if not raw:
        return list(_DEFAULT_CORS_ORIGINS)
    parsed = [o.strip() for o in raw.split(",") if o.strip()]
    return parsed or list(_DEFAULT_CORS_ORIGINS)


def _resolve_under_root(env_var: str, default_relative: str) -> str:
    """env 값(또는 기본 상대경로) 을 ``PROJECT_ROOT`` 기준 절대경로로 정규화.

    - env 값이 없거나 빈 문자열이면 ``PROJECT_ROOT/<default_relative>`` 사용.
    - env 값이 절대경로면 그대로 사용.
    - env 값이 상대경로면 ``PROJECT_ROOT`` 에 join 한다 (cwd 의존 제거).
    """
    raw = os.environ.get(env_var)
    candidate = raw.strip() if raw else ""
    if not candidate:
        return os.path.join(PROJECT_ROOT, default_relative)
    if os.path.isabs(candidate):
        return candidate
    return os.path.join(PROJECT_ROOT, candidate)


UPLOAD_DIR: str = _resolve_under_root("DALLO_UPLOAD_DIR", "uploads")
REPORTS_DIR: str = _resolve_under_root("DALLO_REPORTS_DIR", "reports")
CORS_ORIGINS: List[str] = _parse_cors_origins(
    os.environ.get("DALLO_CORS_ORIGINS"),
)


__all__ = [
    "PROJECT_ROOT",
    "DASHBOARD_DIR",
    "UPLOAD_DIR",
    "REPORTS_DIR",
    "CORS_ORIGINS",
]
