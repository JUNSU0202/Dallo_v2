"""GitHub PR 코멘트 HTTP 어댑터 단위 테스트 (Wave 4-B).

``integrations/github_pr_comment_adapter.post_or_update_pr_comment`` 가
``scripts/post_pr_comment.py::post_comment()`` 가 가지고 있던 GitHub Issues
REST API 호출 책임을 그대로 위임받았는지 검증한다.

검증 포인트:
  - 어댑터 모듈은 ``requests`` 를 top-level 에서 import 하지 않는다
    (lazy import / 더블 주입).
  - 마커 매칭 시 GET → PATCH 순서, POST 미호출, ``status="updated"``.
  - 마커 미스 시 GET → POST, ``status="created"``.
  - 코멘트 0개 시 GET → POST, ``status="created"``.
  - PATCH non-200 시 POST 폴백 (기존 동작 보존).
  - POST non-201 시 ``status="failed"`` 와 raw body 비유출.
  - ``Authorization`` 헤더에만 토큰이 실리고 URL/payload 에는 없다.
  - ``scripts.post_pr_comment.post_comment()`` 가 어댑터에 위임하고
    bool / stdout 동작이 보존된다.
  - AST 검사: ``scripts/post_pr_comment.py`` 본문에 ``requests.{get,patch,post}``
    호출이 남아있지 않고, ``shell=True`` / ``eval`` / ``exec`` 가 없다.
"""

from __future__ import annotations

import ast
import inspect
import os
import sys
from typing import Any, Optional

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from integrations.github_pr_comment_adapter import post_or_update_pr_comment
import scripts.post_pr_comment as post_pr_comment_mod


# ============================================================
# 테스트 더블
# ============================================================


class _FakeResponse:
    def __init__(self, status_code: int, json_payload: Any = None):
        self.status_code = status_code
        self._json = json_payload if json_payload is not None else []

    def json(self):
        return self._json


class _FakeHttpClient:
    """``get`` / ``patch`` / ``post`` 호출 이력을 기록하는 더블."""

    def __init__(
        self,
        get_response: Optional[_FakeResponse] = None,
        patch_response: Optional[_FakeResponse] = None,
        post_response: Optional[_FakeResponse] = None,
    ):
        self.get_response = get_response or _FakeResponse(200, [])
        self.patch_response = patch_response or _FakeResponse(200, {"id": 999})
        self.post_response = post_response or _FakeResponse(201, {"id": 1234})
        self.calls: list[dict] = []

    def get(self, url, **kwargs):
        self.calls.append({"method": "GET", "url": url, "kwargs": dict(kwargs)})
        return self.get_response

    def patch(self, url, **kwargs):
        self.calls.append({"method": "PATCH", "url": url, "kwargs": dict(kwargs)})
        return self.patch_response

    def post(self, url, **kwargs):
        self.calls.append({"method": "POST", "url": url, "kwargs": dict(kwargs)})
        return self.post_response


# ============================================================
# 어댑터 모듈 surface
# ============================================================


def _calls_with_shell_true(tree: ast.AST) -> list[ast.Call]:
    out: list[ast.Call] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    out.append(node)
    return out


def _direct_requests_method_calls(tree: ast.AST, methods: set[str]) -> list[int]:
    """``requests.<method>(...)`` 형태 직접 호출의 라인 번호."""
    lines: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in methods
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "requests"
        ):
            lines.append(node.lineno)
    return lines


class TestAdapterModuleSurface:
    def test_no_top_level_requests_import(self):
        """모듈 본문에 top-level ``import requests`` / ``from requests`` 가 없다."""
        from integrations import github_pr_comment_adapter as mod

        tree = ast.parse(inspect.getsource(mod))
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "requests", (
                        "어댑터는 top-level 에서 requests 를 import 하지 않는다 "
                        "(lazy import 또는 http_client 주입)"
                    )
            if isinstance(node, ast.ImportFrom):
                assert node.module != "requests"

    def test_no_shell_true_or_dangerous_calls(self):
        from integrations import github_pr_comment_adapter as mod

        src = inspect.getsource(mod)
        assert "shell=True" not in src
        assert "os.system" not in src
        assert "os.popen" not in src
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec"}


# ============================================================
# 어댑터 동작
# ============================================================


class TestPostOrUpdatePRCommentBehavior:
    def test_existing_marked_comment_is_patched_and_no_post(self):
        marker = "🔍 Dallo 보안 분석 결과"
        existing_comments = [
            {"id": 11, "url": "https://api.github.com/comments/11",
             "body": "다른 봇 코멘트"},
            {"id": 22, "url": "https://api.github.com/comments/22",
             "body": f"## {marker}\n이전 분석 결과"},
        ]
        client = _FakeHttpClient(
            get_response=_FakeResponse(200, existing_comments),
            patch_response=_FakeResponse(200, {"id": 22}),
        )

        result = post_or_update_pr_comment(
            token="x",
            repo="o/r",
            pr_number=7,
            body="새 본문",
            http_client=client,
        )

        assert result["status"] == "updated"
        assert result["comment_id"] == 22
        assert "ID: 22" in result["message"]

        methods = [c["method"] for c in client.calls]
        assert methods == ["GET", "PATCH"], "POST 가 호출되어선 안 된다"
        # PATCH 는 마커 매칭된 코멘트 url 로 가야 함
        patch_call = client.calls[1]
        assert patch_call["url"] == "https://api.github.com/comments/22"
        assert patch_call["kwargs"]["json"] == {"body": "새 본문"}

    def test_existing_comments_without_marker_creates_new(self):
        existing_comments = [
            {"id": 1, "url": "https://api.github.com/comments/1",
             "body": "관계 없는 코멘트"},
        ]
        client = _FakeHttpClient(
            get_response=_FakeResponse(200, existing_comments),
            post_response=_FakeResponse(201, {"id": 555}),
        )

        result = post_or_update_pr_comment(
            token="x", repo="o/r", pr_number=1, body="b", http_client=client,
        )

        assert result["status"] == "created"
        assert result["comment_id"] == 555
        assert "PR 코멘트 생성 완료" in result["message"]
        methods = [c["method"] for c in client.calls]
        assert methods == ["GET", "POST"]

    def test_no_comments_creates_new(self):
        client = _FakeHttpClient(
            get_response=_FakeResponse(200, []),
            post_response=_FakeResponse(201, {"id": 9}),
        )

        result = post_or_update_pr_comment(
            token="x", repo="o/r", pr_number=2, body="b", http_client=client,
        )

        assert result["status"] == "created"
        assert result["comment_id"] == 9
        methods = [c["method"] for c in client.calls]
        assert methods == ["GET", "POST"]

    def test_get_non_200_skips_patch_and_creates_new(self):
        # GET 이 200 이 아니면 마커 검사 자체를 건너뛰고 바로 POST 로 폴백.
        client = _FakeHttpClient(
            get_response=_FakeResponse(404, {"message": "not found"}),
            post_response=_FakeResponse(201, {"id": 1}),
        )
        result = post_or_update_pr_comment(
            token="x", repo="o/r", pr_number=3, body="b", http_client=client,
        )
        assert result["status"] == "created"
        methods = [c["method"] for c in client.calls]
        assert methods == ["GET", "POST"]

    def test_patch_non_200_falls_through_to_post(self):
        # 기존 동작 보존: PATCH 가 200 이 아니면 새 코멘트로 폴백 생성.
        marker = "🔍 Dallo 보안 분석 결과"
        existing_comments = [
            {"id": 22, "url": "https://api.github.com/comments/22",
             "body": f"## {marker}"},
        ]
        client = _FakeHttpClient(
            get_response=_FakeResponse(200, existing_comments),
            patch_response=_FakeResponse(403, {"message": "forbidden"}),
            post_response=_FakeResponse(201, {"id": 77}),
        )

        result = post_or_update_pr_comment(
            token="x", repo="o/r", pr_number=4, body="b", http_client=client,
        )

        assert result["status"] == "created"
        assert result["comment_id"] == 77
        methods = [c["method"] for c in client.calls]
        assert methods == ["GET", "PATCH", "POST"]

    def test_post_failure_returns_failed_without_raw_body(self):
        # 실패 메시지에 raw response body / 토큰이 새어선 안 된다.
        token_value = "secret-token-do-not-leak"
        suspicious = "<script>alert(1)</script>" + token_value
        client = _FakeHttpClient(
            get_response=_FakeResponse(200, []),
            post_response=_FakeResponse(500, {"message": suspicious}),
        )

        result = post_or_update_pr_comment(
            token=token_value,
            repo="o/r",
            pr_number=5,
            body="b",
            http_client=client,
        )

        assert result["status"] == "failed"
        assert result["comment_id"] is None
        assert "500" in result["message"]
        # 안전성: 실패 메시지에 raw 응답 본문/토큰이 포함돼선 안 됨.
        assert suspicious not in result["message"]
        assert token_value not in result["message"]

    def test_token_only_in_authorization_header(self):
        token_value = "x"
        client = _FakeHttpClient(
            get_response=_FakeResponse(200, []),
            post_response=_FakeResponse(201, {"id": 1}),
        )
        post_or_update_pr_comment(
            token=token_value,
            repo="o/r",
            pr_number=6,
            body="b",
            http_client=client,
        )
        for call in client.calls:
            # URL 에는 토큰이 노출되지 않아야 한다.
            assert token_value not in call["url"] or call["url"].count(token_value) == 0
            # json payload 에 토큰이 들어가지 않아야 한다.
            payload = call["kwargs"].get("json")
            if payload is not None:
                assert token_value not in repr(payload)
            # Authorization 헤더에는 정확히 ``Bearer <token>`` 가 들어간다.
            headers = call["kwargs"].get("headers", {})
            assert headers.get("Authorization") == f"Bearer {token_value}"
            assert headers.get("Accept") == "application/vnd.github.v3+json"

    def test_marker_override_is_respected(self):
        custom_marker = "<<MY-MARKER>>"
        existing_comments = [
            {"id": 1, "url": "https://api.github.com/comments/1",
             "body": "## 🔍 Dallo 보안 분석 결과"},  # 기본 마커: 매칭 안 돼야 함
            {"id": 2, "url": "https://api.github.com/comments/2",
             "body": f"prefix {custom_marker} suffix"},
        ]
        client = _FakeHttpClient(
            get_response=_FakeResponse(200, existing_comments),
            patch_response=_FakeResponse(200, {"id": 2}),
        )

        result = post_or_update_pr_comment(
            token="x",
            repo="o/r",
            pr_number=8,
            body="b",
            marker=custom_marker,
            http_client=client,
        )

        assert result["status"] == "updated"
        assert result["comment_id"] == 2

    def test_lazy_import_uses_requests_module_when_no_client(self, monkeypatch):
        # ``http_client`` 미주입 시 ``_default_http_client`` 가 ``requests``
        # 모듈을 lazy import 해서 사용한다 — 실제 네트워크 호출은 없다.
        from integrations import github_pr_comment_adapter as mod

        class _StubRequests:
            def __init__(self):
                self.calls: list[str] = []

            def get(self, url, **kwargs):
                self.calls.append("get")
                return _FakeResponse(200, [])

            def patch(self, url, **kwargs):
                self.calls.append("patch")
                return _FakeResponse(200, {"id": 0})

            def post(self, url, **kwargs):
                self.calls.append("post")
                return _FakeResponse(201, {"id": 42})

        stub = _StubRequests()
        monkeypatch.setattr(mod, "_default_http_client", lambda: stub)

        result = mod.post_or_update_pr_comment(
            token="x", repo="o/r", pr_number=9, body="b",
        )

        assert result["status"] == "created"
        assert stub.calls == ["get", "post"]


# ============================================================
# scripts/post_pr_comment.py 위임 동작
# ============================================================


class TestPostCommentScriptDelegatesToAdapter:
    def test_post_comment_returns_true_on_updated(self, monkeypatch, capsys):
        def _fake_adapter(**kwargs):
            assert kwargs["token"] == "x"
            assert kwargs["repo"] == "o/r"
            assert kwargs["pr_number"] == 1
            assert kwargs["body"] == "B"
            return {
                "status": "updated",
                "comment_id": 42,
                "message": "[+] 기존 PR 코멘트 업데이트 완료 (ID: 42)",
            }

        monkeypatch.setattr(
            post_pr_comment_mod,
            "post_or_update_pr_comment",
            _fake_adapter,
        )

        ok = post_pr_comment_mod.post_comment("x", "o/r", 1, "B")
        out = capsys.readouterr().out
        assert ok is True
        assert "기존 PR 코멘트 업데이트 완료 (ID: 42)" in out

    def test_post_comment_returns_true_on_created(self, monkeypatch, capsys):
        monkeypatch.setattr(
            post_pr_comment_mod,
            "post_or_update_pr_comment",
            lambda **kw: {
                "status": "created",
                "comment_id": 7,
                "message": "[+] PR 코멘트 생성 완료",
            },
        )
        ok = post_pr_comment_mod.post_comment("x", "o/r", 2, "B")
        out = capsys.readouterr().out
        assert ok is True
        assert "PR 코멘트 생성 완료" in out

    def test_post_comment_returns_false_on_failed(self, monkeypatch, capsys):
        monkeypatch.setattr(
            post_pr_comment_mod,
            "post_or_update_pr_comment",
            lambda **kw: {
                "status": "failed",
                "comment_id": None,
                "message": "[!] PR 코멘트 생성 실패: 500",
            },
        )
        ok = post_pr_comment_mod.post_comment("x", "o/r", 3, "B")
        out = capsys.readouterr().out
        assert ok is False
        assert "PR 코멘트 생성 실패: 500" in out


# ============================================================
# scripts/post_pr_comment.py — requests 직접 호출 제거 / 안전성
# ============================================================


class TestPostPRCommentScriptModuleSurface:
    def test_script_no_longer_calls_requests_directly(self):
        src = inspect.getsource(post_pr_comment_mod)
        tree = ast.parse(src)
        offenders = _direct_requests_method_calls(
            tree, {"get", "patch", "post"}
        )
        assert offenders == [], (
            "scripts/post_pr_comment.py 본문은 requests.{get,patch,post} 를 "
            "직접 호출하지 않아야 한다 (어댑터 위임)."
        )

    def test_script_no_shell_true_or_dangerous_calls(self):
        src = inspect.getsource(post_pr_comment_mod)
        assert "shell=True" not in src
        assert "os.system" not in src
        assert "os.popen" not in src
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec"}


__all__: list[str] = []
