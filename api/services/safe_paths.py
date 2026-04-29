"""안전한 파일명/경로 헬퍼 (api/services/safe_paths.py).

Wave 3-B: 라우터/서비스에 흩어져 있던 동일한 sanitize 로직을 단일 모듈로
모은다. 기존 호출 지점은 다음과 같았다.

- ``api/routers/report.py::_safe_report_filename`` —
  ``filename.replace("/", "_").replace("\\", "_")``
- ``api/services/patch_application.py::sanitize_filename`` — 동일 표현식
- ``api/services/analysis_pipeline.py`` / ``api/routers/report.py`` —
  ``os.path.basename(v)`` 로 다운로드 URL 의 파일명만 노출

설계 원칙:
  - FastAPI / api.server 를 import 하지 않는다 (라우터·서비스 양쪽에서
    순환 import 위험 없이 안전하게 사용 가능).
  - 동작 보존이 최우선이다. 기존 inline 동작에 비해 엄격해지면 응답
    셰이프/상태 코드/폴백 동작이 회귀할 수 있으므로, ``..`` 같은 트래버설
    유사 입력도 문자 치환만 한다 (e.g. ``../secret.html`` → ``.._secret.html``).
    호출자(예: 다운로드 라우터)는 sanitize 후 ``REPORTS_DIR`` 밖을 가리키지
    않도록 ``os.path.exists`` 체크와 결합해 자연 차단된다.
  - 빈 문자열/None 등 비정상 입력에 한해서만 ``default`` 로 폴백한다.
"""

from __future__ import annotations

import os


_DEFAULT_NAME = "report"


def sanitize_filename(value: str, default: str = _DEFAULT_NAME) -> str:
    """파일명의 ``/`` 와 ``\\`` 를 ``_`` 로 평탄화한다.

    - 트래버설 segment(``..``)는 별도로 자르지 않는다 — 슬래시 치환만으로도
      ``REPORTS_DIR`` / ``applied/`` 밖을 직접 가리킬 수 없게 된다 (기존 동작 유지).
    - ``value`` 가 빈 문자열/None 이면 ``default`` 로 폴백한다.
    """
    if not value:
        return default
    return value.replace("/", "_").replace("\\", "_")


def report_download_basename(path: str) -> str:
    """다운로드 URL 에 노출할 파일명만 뽑는다 (디렉터리 prefix 노출 차단).

    리포트 생성 결과의 절대/상대 경로에서 파일명만 잘라 클라이언트에
    공개되는 ``/api/report/download/{name}`` URL 을 구성할 때 쓴다.
    """
    return os.path.basename(path)


__all__ = ["sanitize_filename", "report_download_basename"]
