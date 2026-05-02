"""SonarQube REST API HTTP 어댑터 (analyzer/sonar_http_client.py).

Wave 3-I: ``SonarRunner`` 가 직접 호출하던 ``requests.get(...)`` HTTP 경계를
infrastructure adapter 로 분리한다. ``SonarRunner`` 는 URL 구성, 응답 파싱,
한국어 에러 분기에 집중하고, 본 모듈은 외부 HTTP I/O 책임만 진다
(Clean Architecture: 외부 시스템 어댑터).

설계 원칙:
  - ``requests.get`` 호출은 본 모듈에만 존재한다. 호출자가 ``requests`` 를
    직접 import 하지 않아도 되도록 예외 클래스 alias 도 함께 노출한다.
  - 호출자는 ``SonarRunner(http_client=...)`` 로 더블을 주입해 실제 네트워크
    I/O 를 차단할 수 있다.
  - ``requests.RequestException`` / ``requests.ConnectionError`` 는 그대로
    전파해 호출자의 기존 에러 분기(한국어 메시지/result.error 채움)를
    유지한다.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Tuple

import requests


HttpRequestError = requests.RequestException
HttpConnectionError = requests.ConnectionError


class SonarHttpClient:
    """SonarQube REST API GET 호출만 담당하는 얇은 어댑터.

    - 단일 ``get`` 메서드만 노출한다 (필요 최소면적).
    - URL/params/auth/timeout 은 호출자가 그대로 결정한다(본 어댑터는 SonarQube
      REST 엔드포인트 셋업을 알지 않는다).
    - 반환값은 ``requests.Response`` 객체 그대로다. 호출자가 ``status_code`` /
      ``json()`` / ``raise_for_status()`` 를 기존 방식대로 사용한다.
    """

    def get(
        self,
        url: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: int = 30,
    ):
        return requests.get(url, params=params, auth=auth, timeout=timeout)


__all__ = ["HttpConnectionError", "HttpRequestError", "SonarHttpClient"]
