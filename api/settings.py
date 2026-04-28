"""애플리케이션 부트스트랩 설정 (api/settings.py).

Wave 2-H: api/server.py 와 api/routers/* 에 흩어져 있던 경로/CORS 기본값을
한 곳으로 모은 단일 소스 오브 트루스. FastAPI/DB/Celery 의존성을 갖지 않으며,
임포트만으로 디렉터리 생성 같은 부수효과를 일으키지 않는다.

기본값은 기존 동작과 동일하다. 필요 시 다음 환경변수로 오버라이드 가능:
  - ``DALLO_UPLOAD_DIR`` : 업로드/패치 적용 디렉터리 (기본 ``"uploads"``)
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


UPLOAD_DIR: str = os.environ.get("DALLO_UPLOAD_DIR", "uploads")
CORS_ORIGINS: List[str] = _parse_cors_origins(
    os.environ.get("DALLO_CORS_ORIGINS"),
)


__all__ = [
    "PROJECT_ROOT",
    "DASHBOARD_DIR",
    "UPLOAD_DIR",
    "CORS_ORIGINS",
]
