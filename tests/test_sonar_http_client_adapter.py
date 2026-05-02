"""SonarHttpClient 어댑터 단위 테스트 (Wave 3-I).

``analyzer/sonar_http_client.py`` 가 ``requests.get`` HTTP 호출을 단일 지점
에서 책임지고, ``SonarRunner`` 가 호출하는 인터페이스(``get(url, *,
params=None, auth=None, timeout=...)``)를 안정적으로 노출하는지 검증한다.

검증 포인트:
  - ``SonarHttpClient.get`` 은 url/params/auth/timeout 을 그대로
    ``requests.get`` 으로 전달한다 (단순 패스스루).
  - 인자 누락 시 기본값(params=None, auth=None, timeout=30) 이 적용된다.
  - ``requests.RequestException`` / ``ConnectionError`` 는 alias 로 노출되어
    ``SonarRunner`` 가 ``requests`` 를 직접 import 하지 않아도 된다.
  - 모듈 본문에 ``shell=True`` / ``eval`` / ``exec`` 가 없다.
"""

from __future__ import annotations

import ast
import inspect

import pytest
import requests

from analyzer.sonar_http_client import (
    HttpConnectionError,
    HttpRequestError,
    SonarHttpClient,
)


# ============================================================
# 모듈 surface
# ============================================================


class TestSonarHttpClientModuleSurface:
    def test_no_shell_true_or_dangerous_calls(self):
        from analyzer import sonar_http_client as mod

        src = inspect.getsource(mod)
        assert "shell=True" not in src
        assert "os.system" not in src
        assert "os.popen" not in src
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec"}

    def test_exception_aliases_are_re_exported(self):
        # ``SonarRunner`` 가 requests 를 직접 import 하지 않아도 되도록 alias 가
        # ``requests`` 의 실제 예외 클래스와 동일해야 한다.
        assert HttpRequestError is requests.RequestException
        assert HttpConnectionError is requests.ConnectionError


# ============================================================
# get() 위임 동작 — requests.get 으로 인자 패스스루
# ============================================================


class _RecordingRequestsGet:
    def __init__(self, response):
        self._response = response
        self.calls: list[dict] = []

    def __call__(self, url, **kwargs):
        self.calls.append({"url": url, "kwargs": dict(kwargs)})
        return self._response


class TestSonarHttpClientGet:
    def test_get_passes_all_kwargs_to_requests_get(self, monkeypatch):
        sentinel = object()
        recorder = _RecordingRequestsGet(sentinel)
        monkeypatch.setattr(
            "analyzer.sonar_http_client.requests.get", recorder
        )

        client = SonarHttpClient()
        params = {"componentKeys": "p"}
        auth = ("token", "")
        result = client.get(
            "http://x/api/issues/search",
            params=params,
            auth=auth,
            timeout=30,
        )

        assert result is sentinel
        assert len(recorder.calls) == 1
        call = recorder.calls[0]
        assert call["url"] == "http://x/api/issues/search"
        assert call["kwargs"]["params"] is params
        assert call["kwargs"]["auth"] is auth
        assert call["kwargs"]["timeout"] == 30

    def test_get_default_kwargs(self, monkeypatch):
        recorder = _RecordingRequestsGet(object())
        monkeypatch.setattr(
            "analyzer.sonar_http_client.requests.get", recorder
        )

        SonarHttpClient().get("http://x/api/system/status")

        kwargs = recorder.calls[0]["kwargs"]
        assert kwargs["params"] is None
        assert kwargs["auth"] is None
        assert kwargs["timeout"] == 30

    def test_get_propagates_request_exception(self, monkeypatch):
        def _raise(url, **kw):
            raise HttpRequestError("boom")

        monkeypatch.setattr("analyzer.sonar_http_client.requests.get", _raise)

        with pytest.raises(HttpRequestError):
            SonarHttpClient().get("http://x")

    def test_get_propagates_connection_error(self, monkeypatch):
        def _raise(url, **kw):
            raise HttpConnectionError("no host")

        monkeypatch.setattr("analyzer.sonar_http_client.requests.get", _raise)

        with pytest.raises(HttpConnectionError):
            SonarHttpClient().get("http://x")


__all__: list[str] = []
