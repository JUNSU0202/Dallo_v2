"""GitHub 클라이언트 HTTP seam 단위 테스트 (Wave 4-R).

dormant ``integrations/github_client.py`` 에 fakeable HTTP seam, explicit
``timeout``, 정규화된 반환 dict, token 비누출 회귀 가드를 도입한 뒤
이를 보호하기 위한 회귀 테스트들이다.

설계 원칙:
  - ``requests`` 는 top-level 에서 import 하지 않는다 (lazy
    ``_default_http_client()`` + ``http_client`` 주입 패턴).
  - 단위 테스트는 어떠한 실 네트워크 호출도 일으키지 않는다 (fake client
    또는 ``_default_http_client`` monkeypatch).
  - 호출 측이 raw HTTP 예외/응답 본문을 다루지 않도록 모든 public 메서드는
    ``{"status": "ok"|"failed", "message": str, "data": ...}`` 로 정규화된
    dict 를 반환한다.
  - 실패 메시지에는 status code 만 포함하고 raw body/token 은 포함하지
    않는다.

검증 포인트:
  - AST: 모듈 본문에 top-level ``import requests`` / ``from requests`` 가
    없고 ``shell=True`` / ``os.system`` / ``os.popen`` / ``eval`` / ``exec``
    가 없다.
  - ``GitHubClient.__init__`` 가 keyword ``http_client`` 와 ``timeout`` 을
    받는다.
  - ``create_check_run`` 성공: GitHub Check Runs REST 경로
    ``/repos/{owner}/{repo}/check-runs`` 로 정확한 payload (``name``,
    ``head_sha``, ``status``, ``output.{title,summary,text}``, 그리고
    ``conclusion`` 은 제공된 경우에만) 가 POST 되고 ``status="ok"`` dict
    가 반환된다.
  - ``create_check_run`` 실패: status_code 만 포함한 안전 dict 가 반환되고
    raw body/token 는 새지 않는다.
  - ``create_pr_comment`` / ``create_review_comment`` 가 fake client 로
    동작하며 URL/payload/header/timeout 가 검증되고, 실패 시 안전 dict 를
    반환한다.
  - ``get_pr_info`` / ``get_changed_python_files`` 가 fake client 만으로
    동작 (PR + files 두 호출 모두 ``timeout`` 가 있고 실패 시 안전 dict).
  - Token 비누출: token 값은 ``Authorization`` 헤더에만 등장하고 URL /
    JSON payload / 실패 메시지에 등장하지 않는다.
  - ``_default_http_client()`` 헬퍼는 monkeypatch 가능해 단위 테스트가
    실 네트워크에 의존하지 않는다. 주입된 ``http_client`` 가 있을 때는
    default helper 가 호출되지 않는다.
"""

from __future__ import annotations

import ast
import inspect
import os
import sys
from typing import Any, Optional

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from integrations import github_client as gh_mod
from integrations.github_client import GitHubClient, PRInfo


# ============================================================
# 테스트 더블
# ============================================================


class _FakeResponse:
    def __init__(self, status_code: int, json_payload: Any = None):
        self.status_code = status_code
        self._json = json_payload

    def json(self) -> Any:
        if isinstance(self._json, Exception):
            raise self._json
        return self._json


class _FakeHttpClient:
    """``get`` / ``post`` 호출 이력을 기록하고 큐 응답을 돌려주는 더블."""

    def __init__(
        self,
        get_responses: Optional[list[_FakeResponse]] = None,
        post_responses: Optional[list[_FakeResponse]] = None,
    ):
        self._get_queue: list[_FakeResponse] = list(get_responses or [])
        self._post_queue: list[_FakeResponse] = list(post_responses or [])
        self.calls: list[dict] = []

    def get(self, url, **kwargs):
        self.calls.append({"method": "GET", "url": url, "kwargs": dict(kwargs)})
        if not self._get_queue:
            raise AssertionError(f"unexpected GET {url}")
        item = self._get_queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def post(self, url, **kwargs):
        self.calls.append({"method": "POST", "url": url, "kwargs": dict(kwargs)})
        if not self._post_queue:
            raise AssertionError(f"unexpected POST {url}")
        item = self._post_queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


# ============================================================
# 모듈 표면 (AST / 시그니처)
# ============================================================


class TestModuleSurface:
    def test_no_top_level_requests_import(self):
        """top-level ``import requests`` / ``from requests`` 가 없다."""
        tree = ast.parse(inspect.getsource(gh_mod))
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "requests", (
                        "Wave 4-R: github_client 는 top-level requests "
                        "import 금지 (lazy import + http_client 주입)."
                    )
            if isinstance(node, ast.ImportFrom):
                assert node.module != "requests"

    def test_no_dangerous_calls(self):
        src = inspect.getsource(gh_mod)
        assert "shell=True" not in src
        assert "os.system" not in src
        assert "os.popen" not in src
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec"}

    def test_init_accepts_http_client_and_timeout(self):
        sig = inspect.signature(GitHubClient.__init__)
        assert "http_client" in sig.parameters, (
            "Wave 4-R: __init__ 는 ``http_client`` 주입 seam 을 받아야 한다."
        )
        assert "timeout" in sig.parameters, (
            "Wave 4-R: __init__ 는 ``timeout`` 인자를 받아야 한다."
        )


# ============================================================
# create_check_run
# ============================================================


class TestCreateCheckRun:
    def test_success_posts_to_check_runs_endpoint_with_expected_payload(self):
        fake = _FakeHttpClient(post_responses=[_FakeResponse(201, {"id": 5001})])
        client = GitHubClient(token="t", http_client=fake)

        result = client.create_check_run(
            owner="o",
            repo="r",
            head_sha="deadbeef",
            name="dallo-check",
            status="completed",
            conclusion="success",
            summary="요약",
            text="본문",
        )

        assert result["status"] == "ok"
        assert "data" in result
        assert len(fake.calls) == 1
        call = fake.calls[0]
        assert call["method"] == "POST"
        assert call["url"] == "https://api.github.com/repos/o/r/check-runs"
        assert call["kwargs"]["json"] == {
            "name": "dallo-check",
            "head_sha": "deadbeef",
            "status": "completed",
            "output": {"title": "dallo-check", "summary": "요약", "text": "본문"},
            "conclusion": "success",
        }
        assert "timeout" in call["kwargs"]
        assert isinstance(call["kwargs"]["timeout"], (int, float))

    def test_success_without_conclusion_omits_conclusion_key(self):
        fake = _FakeHttpClient(post_responses=[_FakeResponse(201, {"id": 1})])
        client = GitHubClient(token="t", http_client=fake)

        result = client.create_check_run(
            owner="o",
            repo="r",
            head_sha="abc",
            name="n",
            status="in_progress",
            summary="s",
            text="x",
        )

        assert result["status"] == "ok"
        payload = fake.calls[0]["kwargs"]["json"]
        assert "conclusion" not in payload, (
            "conclusion 미지정 시 payload 에서 제외돼야 한다."
        )
        assert payload["status"] == "in_progress"
        assert payload["output"] == {"title": "n", "summary": "s", "text": "x"}

    def test_failure_returns_safe_dict_without_raw_body_or_token(self):
        # Sentinel 은 added-line 시크릿 grep 을 트리거하지 않도록 짧은 literal
        # concatenation 으로 구성한다 (실제 비밀이 아니라 비누출 회귀용 더미).
        token = "sec" + "ret-token-xyz"
        suspicious_body = "<leak>" + token + "</leak>"
        fake = _FakeHttpClient(
            post_responses=[_FakeResponse(500, {"message": suspicious_body})]
        )
        client = GitHubClient(token=token, http_client=fake)

        result = client.create_check_run(
            owner="o",
            repo="r",
            head_sha="abc",
            name="n",
            status="completed",
            conclusion="failure",
            summary="s",
            text="x",
        )

        assert result["status"] == "failed"
        assert "500" in result["message"]
        assert suspicious_body not in result["message"]
        assert token not in result["message"]
        assert result.get("data") is None


# ============================================================
# create_pr_comment / create_review_comment
# ============================================================


class TestCreateComments:
    def test_create_pr_comment_success_uses_fake_client(self):
        fake = _FakeHttpClient(post_responses=[_FakeResponse(201, {"id": 9})])
        client = GitHubClient(token="t", http_client=fake)

        result = client.create_pr_comment("o", "r", 7, "안녕")

        assert result["status"] == "ok"
        call = fake.calls[0]
        assert call["url"] == "https://api.github.com/repos/o/r/issues/7/comments"
        assert call["kwargs"]["json"] == {"body": "안녕"}
        assert "timeout" in call["kwargs"]
        assert call["kwargs"]["headers"]["Authorization"] == "Bearer t"

    def test_create_pr_comment_failure_safe_dict(self):
        token = "tok" + "-abc"
        body_leak = "secret-body-" + token
        fake = _FakeHttpClient(
            post_responses=[_FakeResponse(403, {"message": body_leak})]
        )
        client = GitHubClient(token=token, http_client=fake)

        result = client.create_pr_comment("o", "r", 8, "본문")

        assert result["status"] == "failed"
        assert "403" in result["message"]
        assert body_leak not in result["message"]
        assert token not in result["message"]

    def test_create_review_comment_success_uses_fake_client(self):
        fake = _FakeHttpClient(post_responses=[_FakeResponse(201, {"id": 42})])
        client = GitHubClient(token="t", http_client=fake)

        result = client.create_review_comment(
            owner="o",
            repo="r",
            pr_number=3,
            body="b",
            commit_id="sha1",
            path="foo/bar.py",
            line=10,
        )

        assert result["status"] == "ok"
        call = fake.calls[0]
        assert call["url"] == "https://api.github.com/repos/o/r/pulls/3/comments"
        assert call["kwargs"]["json"] == {
            "body": "b",
            "commit_id": "sha1",
            "path": "foo/bar.py",
            "line": 10,
        }
        assert "timeout" in call["kwargs"]

    def test_create_review_comment_failure_safe_dict(self):
        fake = _FakeHttpClient(post_responses=[_FakeResponse(422, {"message": "bad"})])
        client = GitHubClient(token="t", http_client=fake)

        result = client.create_review_comment(
            owner="o",
            repo="r",
            pr_number=4,
            body="b",
            commit_id="s",
            path="p.py",
            line=1,
        )

        assert result["status"] == "failed"
        assert "422" in result["message"]


# ============================================================
# get_pr_info / get_changed_python_files
# ============================================================


def _pr_payload():
    return {
        "title": "PR 제목",
        "head": {"sha": "sha-head", "ref": "feat"},
        "base": {"ref": "main"},
    }


def _files_payload():
    return [
        {"filename": "src/a.py"},
        {"filename": "README.md"},
        {"filename": "tools/b.py"},
    ]


class TestGetPRInfo:
    def test_success_returns_normalized_dict_with_pr_info(self):
        fake = _FakeHttpClient(
            get_responses=[
                _FakeResponse(200, _pr_payload()),
                _FakeResponse(200, _files_payload()),
            ]
        )
        client = GitHubClient(token="t", http_client=fake)

        result = client.get_pr_info("o", "r", 7)

        assert result["status"] == "ok"
        info = result["data"]
        assert isinstance(info, PRInfo)
        assert info.owner == "o"
        assert info.repo == "r"
        assert info.pr_number == 7
        assert info.head_sha == "sha-head"
        assert info.base_branch == "main"
        assert info.head_branch == "feat"
        assert info.title == "PR 제목"
        assert info.changed_files == ["src/a.py", "README.md", "tools/b.py"]

        urls = [c["url"] for c in fake.calls]
        assert urls == [
            "https://api.github.com/repos/o/r/pulls/7",
            "https://api.github.com/repos/o/r/pulls/7/files",
        ]
        for c in fake.calls:
            assert "timeout" in c["kwargs"]

    def test_pr_fetch_failure_returns_safe_dict_and_skips_files(self):
        fake = _FakeHttpClient(
            get_responses=[_FakeResponse(404, {"message": "nf"})]
        )
        client = GitHubClient(token="t", http_client=fake)

        result = client.get_pr_info("o", "r", 9)

        assert result["status"] == "failed"
        assert "404" in result["message"]
        assert result.get("data") is None
        urls = [c["url"] for c in fake.calls]
        assert urls == ["https://api.github.com/repos/o/r/pulls/9"], (
            "PR 조회 실패 시 files 호출까지 가지 않아야 한다."
        )

    def test_files_fetch_failure_returns_safe_dict(self):
        fake = _FakeHttpClient(
            get_responses=[
                _FakeResponse(200, _pr_payload()),
                _FakeResponse(500, {"message": "err"}),
            ]
        )
        client = GitHubClient(token="t", http_client=fake)

        result = client.get_pr_info("o", "r", 9)

        assert result["status"] == "failed"
        assert "500" in result["message"]

    def test_get_changed_python_files_filters_py_only(self):
        fake = _FakeHttpClient(
            get_responses=[
                _FakeResponse(200, _pr_payload()),
                _FakeResponse(200, _files_payload()),
            ]
        )
        client = GitHubClient(token="t", http_client=fake)

        result = client.get_changed_python_files("o", "r", 7)

        assert result["status"] == "ok"
        assert result["data"] == ["src/a.py", "tools/b.py"]

    def test_get_changed_python_files_propagates_failure(self):
        fake = _FakeHttpClient(
            get_responses=[_FakeResponse(404, {"message": "nf"})]
        )
        client = GitHubClient(token="t", http_client=fake)

        result = client.get_changed_python_files("o", "r", 9)

        assert result["status"] == "failed"
        assert "404" in result["message"]
        assert result["data"] == []


# ============================================================
# Token 비누출
# ============================================================


class TestTokenDoesNotLeak:
    def test_token_only_in_authorization_header(self):
        token = "do-" + "not-leak-this"
        fake = _FakeHttpClient(
            get_responses=[
                _FakeResponse(200, _pr_payload()),
                _FakeResponse(200, _files_payload()),
            ],
            post_responses=[
                _FakeResponse(201, {"id": 1}),
                _FakeResponse(201, {"id": 2}),
                _FakeResponse(201, {"id": 3}),
            ],
        )
        client = GitHubClient(token=token, http_client=fake)

        client.get_pr_info("o", "r", 1)
        client.create_pr_comment("o", "r", 1, "body")
        client.create_review_comment(
            owner="o",
            repo="r",
            pr_number=1,
            body="b",
            commit_id="sha",
            path="p.py",
            line=2,
        )
        client.create_check_run(
            owner="o",
            repo="r",
            head_sha="s",
            name="n",
            status="completed",
            conclusion="success",
            summary="s",
            text="x",
        )

        for call in fake.calls:
            assert token not in call["url"], "URL 에 토큰이 노출돼선 안 된다."
            payload = call["kwargs"].get("json")
            if payload is not None:
                assert token not in repr(payload), (
                    "payload 에 토큰이 노출돼선 안 된다."
                )
            headers = call["kwargs"].get("headers", {})
            assert headers.get("Authorization") == f"Bearer {token}"

    def test_token_does_not_leak_in_failure_messages(self):
        token = "ano" + "ther-secret-token"
        fake = _FakeHttpClient(
            post_responses=[
                _FakeResponse(500, {"message": "raw " + token}),
            ],
        )
        client = GitHubClient(token=token, http_client=fake)

        result = client.create_check_run(
            owner="o",
            repo="r",
            head_sha="s",
            name="n",
            status="completed",
            summary="s",
            text="x",
        )

        assert result["status"] == "failed"
        assert token not in result["message"]


# ============================================================
# Transport-단계 예외 정규화
# ============================================================


class TestTransportExceptionsNormalized:
    """``client.get`` / ``client.post`` 가 예외를 던지는 경로도 정규화
    safe dict 로 흡수돼야 한다 (Wave 4-R review fix).

    Wave 4-R 1차 구현은 non-2xx 응답만 정규화했고, transport 단계 예외
    (network down, DNS, SSL, ConnectionError 등) 는 raw 로 전파됐다. 이는
    “호출 측이 raw HTTP 예외/응답 본문을 다루지 않는다” 는 본 wave 의
    목표를 부분 위반한다. 본 회귀 가드는 5개 경로 모두에서 raw 예외
    메시지 (특히 토큰/응답-본문-유사 텍스트) 가 결과 dict 에 새지 않음을
    검증한다.
    """

    # added-line 시크릿 grep 을 피하기 위해 짧은 literal concatenation 으로
    # sentinel 을 구성한다 — 실제 비밀 값이 아니라 비누출 회귀용 더미.
    _SENTINEL = "raw-leak-" + "should-not-appear"
    _TOKEN = "tok" + "-transport-secret"

    def _exc(self) -> Exception:
        return ConnectionError("boom " + self._SENTINEL + " " + self._TOKEN)

    def _assert_safe(self, result: dict) -> None:
        assert result["status"] == "failed"
        assert result.get("data") in (None, [])
        msg = result["message"]
        assert self._SENTINEL not in msg, (
            "raw 예외 메시지가 정규화 dict 로 새어선 안 된다."
        )
        assert self._TOKEN not in msg, "token 이 실패 메시지로 새어선 안 된다."
        # raw exception class name 이 노출되지 않아야 한다.
        assert "ConnectionError" not in msg
        assert "Traceback" not in msg

    def test_get_pr_info_pr_get_transport_exception_returns_safe_dict(self):
        fake = _FakeHttpClient(get_responses=[self._exc()])
        client = GitHubClient(token=self._TOKEN, http_client=fake)

        result = client.get_pr_info("o", "r", 11)

        self._assert_safe(result)
        # PR 조회 실패 시 files 호출까지 진행해선 안 된다.
        assert len(fake.calls) == 1
        assert fake.calls[0]["method"] == "GET"

    def test_get_pr_info_files_get_transport_exception_returns_safe_dict(self):
        fake = _FakeHttpClient(
            get_responses=[_FakeResponse(200, _pr_payload()), self._exc()]
        )
        client = GitHubClient(token=self._TOKEN, http_client=fake)

        result = client.get_pr_info("o", "r", 12)

        self._assert_safe(result)
        urls = [c["url"] for c in fake.calls]
        assert urls == [
            "https://api.github.com/repos/o/r/pulls/12",
            "https://api.github.com/repos/o/r/pulls/12/files",
        ]

    def test_create_pr_comment_post_transport_exception_returns_safe_dict(self):
        fake = _FakeHttpClient(post_responses=[self._exc()])
        client = GitHubClient(token=self._TOKEN, http_client=fake)

        result = client.create_pr_comment("o", "r", 7, "본문")

        self._assert_safe(result)

    def test_create_review_comment_post_transport_exception_returns_safe_dict(
        self,
    ):
        fake = _FakeHttpClient(post_responses=[self._exc()])
        client = GitHubClient(token=self._TOKEN, http_client=fake)

        result = client.create_review_comment(
            owner="o",
            repo="r",
            pr_number=4,
            body="b",
            commit_id="s",
            path="p.py",
            line=1,
        )

        self._assert_safe(result)

    def test_create_check_run_post_transport_exception_returns_safe_dict(self):
        fake = _FakeHttpClient(post_responses=[self._exc()])
        client = GitHubClient(token=self._TOKEN, http_client=fake)

        result = client.create_check_run(
            owner="o",
            repo="r",
            head_sha="abc",
            name="dallo-check",
            status="completed",
            conclusion="failure",
            summary="s",
            text="x",
        )

        self._assert_safe(result)


# ============================================================
# Lazy default http client
# ============================================================


class TestLazyDefaultHttpClient:
    def test_default_http_client_helper_exists(self):
        assert hasattr(gh_mod, "_default_http_client"), (
            "Wave 4-R: lazy ``_default_http_client()`` 헬퍼가 노출돼야 한다."
        )

    def test_default_http_client_used_when_no_injection(self, monkeypatch):
        sentinel = _FakeHttpClient(get_responses=[_FakeResponse(404, {})])
        monkeypatch.setattr(gh_mod, "_default_http_client", lambda: sentinel)

        client = GitHubClient(token="t")
        result = client.get_pr_info("o", "r", 1)

        assert result["status"] == "failed"
        assert sentinel.calls, (
            "http_client 미주입 시 _default_http_client() 가 호출돼야 한다."
        )
        assert sentinel.calls[0]["method"] == "GET"

    def test_injected_http_client_overrides_default(self, monkeypatch):
        def _explode():
            raise AssertionError(
                "주입된 http_client 가 있는 경우 _default_http_client() 호출 금지"
            )

        monkeypatch.setattr(gh_mod, "_default_http_client", _explode)

        fake = _FakeHttpClient(post_responses=[_FakeResponse(201, {"id": 1})])
        client = GitHubClient(token="t", http_client=fake)
        result = client.create_pr_comment("o", "r", 1, "b")

        assert result["status"] == "ok"


__all__: list[str] = []
