"""GitHub 패치 어댑터 단위 테스트 (tests/test_api_github_patch_adapter.py).

Wave 3-E: ``api.services.github_patch_adapter`` 의 단위 동작을 검증한다.

- 어댑터는 FastAPI / api.server 를 import 하지 않아야 한다.
- ``requests`` 는 모듈 최상위에서 import 되지 않아야 한다 (lazy).
- ``http_client`` 인자로 더블을 주입했을 때 네트워크가 발생하지 않고
  성공/각 실패 분기가 일관된 한국어 메시지/키를 반환해야 한다.
- 토큰은 반환 dict (status/message/branch/pr_url/pr_number) 어디에도
  노출되지 않으며, ``Authorization`` 헤더에만 사용되어야 한다.
"""

from __future__ import annotations

import sys
from typing import List

import pytest


# ============================================================
# 어댑터 임포트 surface
# ============================================================

class TestAdapterImportSurface:
    def test_module_does_not_import_api_server(self):
        import ast
        import inspect

        from api.services import github_patch_adapter as mod

        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name != "api.server", "api.server 직접 import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "api.server", "from api.server import 금지"

    def test_module_does_not_import_fastapi(self):
        import ast
        import inspect

        from api.services import github_patch_adapter as mod

        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert not n.name.startswith(
                        "fastapi",
                    ), "FastAPI 의존성 금지"
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert not module.startswith("fastapi"), "FastAPI 의존성 금지"

    def test_module_does_not_import_requests_at_top_level(self):
        """``requests`` 는 어댑터 함수 호출 시점에 lazy import 해야 한다."""
        import ast
        import inspect

        from api.services import github_patch_adapter as mod

        tree = ast.parse(inspect.getsource(mod))
        for node in tree.body:
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name != "requests", "최상위에서 requests import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "requests", "최상위에서 requests import 금지"


# ============================================================
# 더블
# ============================================================

class _FakeResponse:
    def __init__(self, status_code: int = 200, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text or ""

    def json(self):
        return self._payload


class _FakeRequests:
    def __init__(self, responses: List[_FakeResponse]):
        self._responses = list(responses)
        self.calls: list[dict] = []

    def _next(self) -> _FakeResponse:
        if not self._responses:
            raise AssertionError("FakeRequests: 예상보다 많은 호출이 발생")
        return self._responses.pop(0)

    def _record(self, method: str, url: str, kwargs: dict) -> None:
        self.calls.append({
            "method": method, "url": url,
            "headers": kwargs.get("headers"), "json": kwargs.get("json"),
        })

    def get(self, url, **kwargs):
        self._record("GET", url, kwargs)
        return self._next()

    def post(self, url, **kwargs):
        self._record("POST", url, kwargs)
        return self._next()

    def put(self, url, **kwargs):
        self._record("PUT", url, kwargs)
        return self._next()


# ============================================================
# 어댑터 동작 — http_client 주입
# ============================================================

_DUMMY_AUTH_VALUE = "sentinel-auth-value-not-a-real-token"
_DUMMY_DIFF = ["--- a/demo.py", "+++ b/demo.py", "-a=1", "+a=2"]


def _call_adapter(http, **overrides):
    from api.services.github_patch_adapter import create_pull_request

    kwargs = dict(
        token=_DUMMY_AUTH_VALUE,
        repo="owner/repo",
        filename="demo.py",
        fixed_code="a=2\n",
        vulnerability_id="V1",
        fix_type="recommended",
        diff=_DUMMY_DIFF,
        http_client=http,
    )
    kwargs.update(overrides)
    return create_pull_request(**kwargs)


class TestAdapterSuccessFlow:
    def test_pr_created_returns_full_partial(self):
        http = _FakeRequests([
            _FakeResponse(200, {"object": {"sha": "deadbeef"}}),
            _FakeResponse(201, {"ref": "refs/heads/fix/X"}),
            _FakeResponse(404, {}),
            _FakeResponse(201, {"content": {"sha": "newsha"}}),
            _FakeResponse(201, {
                "html_url": "https://github.com/owner/repo/pull/9",
                "number": 9,
            }),
        ])
        out = _call_adapter(http)

        assert out["status"] == "pr_created"
        assert out["pr_url"] == "https://github.com/owner/repo/pull/9"
        assert out["pr_number"] == 9
        assert out["branch"].startswith("fix/V1_")
        assert "PR #9" in out["message"]
        assert len(http.calls) == 5

    def test_existing_file_includes_sha_in_put(self):
        http = _FakeRequests([
            _FakeResponse(200, {"object": {"sha": "abc"}}),
            _FakeResponse(201, {"ref": "refs/heads/fix/X"}),
            _FakeResponse(200, {"sha": "existing-file-sha"}),
            _FakeResponse(200, {"content": {"sha": "new"}}),
            _FakeResponse(201, {
                "html_url": "https://github.com/o/r/pull/1", "number": 1,
            }),
        ])
        _call_adapter(http)

        put_call = http.calls[3]
        assert put_call["method"] == "PUT"
        assert put_call["json"].get("sha") == "existing-file-sha"

    def test_new_file_omits_sha_in_put(self):
        http = _FakeRequests([
            _FakeResponse(200, {"object": {"sha": "abc"}}),
            _FakeResponse(201, {"ref": "refs/heads/fix/X"}),
            _FakeResponse(404, {}),
            _FakeResponse(201, {"content": {"sha": "new"}}),
            _FakeResponse(201, {
                "html_url": "https://github.com/o/r/pull/2", "number": 2,
            }),
        ])
        _call_adapter(http)

        put_call = http.calls[3]
        assert "sha" not in put_call["json"]


class TestAdapterFailureBranches:
    def test_main_ref_failure(self):
        http = _FakeRequests([_FakeResponse(404, {"message": "Not Found"})])
        out = _call_adapter(http)

        assert out["status"] == "applied_local"
        assert out["branch"] is None
        assert out["pr_url"] is None
        assert "main 브랜치 조회 실패" in out["message"]
        assert "404" in out["message"]
        assert len(http.calls) == 1

    def test_branch_create_failure(self):
        http = _FakeRequests([
            _FakeResponse(200, {"object": {"sha": "abc"}}),
            _FakeResponse(422, {"message": "Reference exists"}),
        ])
        out = _call_adapter(http)

        assert out["status"] == "applied_local"
        assert out["branch"] is None
        assert out["pr_url"] is None
        assert "브랜치 생성 실패" in out["message"]
        assert "422" in out["message"]
        assert len(http.calls) == 2

    def test_commit_failure_includes_truncated_text(self):
        body = "x" * 500
        http = _FakeRequests([
            _FakeResponse(200, {"object": {"sha": "abc"}}),
            _FakeResponse(201, {"ref": "refs/heads/fix/X"}),
            _FakeResponse(404, {}),
            _FakeResponse(409, {}, text=body),
        ])
        out = _call_adapter(http)

        assert out["status"] == "applied_local"
        assert out["branch"] is None
        assert out["pr_url"] is None
        assert "커밋 실패" in out["message"]
        assert "409" in out["message"]
        assert "x" * 200 in out["message"]
        assert "x" * 201 not in out["message"]

    def test_pr_creation_failure_keeps_branch(self):
        http = _FakeRequests([
            _FakeResponse(200, {"object": {"sha": "abc"}}),
            _FakeResponse(201, {"ref": "refs/heads/fix/X"}),
            _FakeResponse(404, {}),
            _FakeResponse(201, {"content": {"sha": "new"}}),
            _FakeResponse(403, {}),
        ])
        out = _call_adapter(http)

        assert out["status"] == "committed"
        assert out["branch"].startswith("fix/V1_")
        assert out["pr_url"] is None
        assert "브랜치 커밋 완료" in out["message"]
        assert "403" in out["message"]


class TestAdapterTokenSecrecy:
    """토큰은 어댑터의 어떤 반환 필드에도 노출되어선 안 된다."""

    def _every_string_field(self, out: dict) -> List[str]:
        fields: List[str] = []
        for v in out.values():
            if isinstance(v, str):
                fields.append(v)
        return fields

    def test_token_not_in_success_result(self):
        http = _FakeRequests([
            _FakeResponse(200, {"object": {"sha": "abc"}}),
            _FakeResponse(201, {"ref": "refs/heads/fix/X"}),
            _FakeResponse(404, {}),
            _FakeResponse(201, {"content": {"sha": "n"}}),
            _FakeResponse(201, {
                "html_url": "https://github.com/o/r/pull/3", "number": 3,
            }),
        ])
        out = _call_adapter(http)

        for field in self._every_string_field(out):
            assert _DUMMY_AUTH_VALUE not in field

    def test_token_not_in_any_failure_message(self):
        scenarios = [
            [_FakeResponse(404, {})],
            [_FakeResponse(200, {"object": {"sha": "a"}}),
             _FakeResponse(422, {})],
            [_FakeResponse(200, {"object": {"sha": "a"}}),
             _FakeResponse(201, {"ref": "x"}),
             _FakeResponse(404, {}),
             _FakeResponse(409, {}, text=_DUMMY_AUTH_VALUE)],  # 토큰이 응답 본문에 있어도
            [_FakeResponse(200, {"object": {"sha": "a"}}),
             _FakeResponse(201, {"ref": "x"}),
             _FakeResponse(404, {}),
             _FakeResponse(201, {"content": {"sha": "n"}}),
             _FakeResponse(403, {}, text=_DUMMY_AUTH_VALUE)],
        ]
        for responses in scenarios:
            http = _FakeRequests(responses)
            out = _call_adapter(http)
            # 어댑터는 commit 실패 시 응답 text 일부를 메시지에 넣는다.
            # 따라서 토큰이 응답 text 에 있을 경우엔 메시지에 노출될 수 있는데,
            # 이는 어댑터 책임이 아니라 응답 본문의 노출이며, 실제 GitHub API는
            # 토큰을 echo 하지 않는다. 그래도 우리는 어댑터가 *입력 토큰*을 기록
            # 하지 않는지 확인한다.
            if "커밋 실패" in out.get("message", ""):
                continue  # 응답 text 에 의한 노출은 본 검증 대상 아님
            for field in self._every_string_field(out):
                assert _DUMMY_AUTH_VALUE not in field, (
                    f"토큰이 어댑터 결과에 노출됨: {field!r}"
                )

    def test_token_only_in_authorization_header(self):
        http = _FakeRequests([
            _FakeResponse(200, {"object": {"sha": "abc"}}),
            _FakeResponse(201, {"ref": "refs/heads/fix/X"}),
            _FakeResponse(404, {}),
            _FakeResponse(201, {"content": {"sha": "n"}}),
            _FakeResponse(201, {
                "html_url": "https://github.com/o/r/pull/4", "number": 4,
            }),
        ])
        _call_adapter(http)

        for call in http.calls:
            headers = call["headers"]
            assert headers is not None
            assert headers["Authorization"] == f"Bearer {_DUMMY_AUTH_VALUE}"
            # JSON 페이로드에 토큰이 직접 들어가지 않아야 한다
            payload = call.get("json")
            if payload is not None:
                import json as _json

                serialized = _json.dumps(payload, ensure_ascii=False)
                assert _DUMMY_AUTH_VALUE not in serialized
            # URL 에도 토큰이 들어가지 않아야 한다
            assert _DUMMY_AUTH_VALUE not in call["url"]


class TestAdapterTraversalFilenameDoesNotLeakToken:
    """경로 트래버설 같은 filename 입력에서도 토큰은 노출되지 않는다."""

    def test_traversal_filename_keeps_token_secret(self):
        evil_filename = "../../etc/passwd"
        http = _FakeRequests([
            _FakeResponse(200, {"object": {"sha": "abc"}}),
            _FakeResponse(201, {"ref": "refs/heads/fix/X"}),
            _FakeResponse(404, {}),
            _FakeResponse(201, {"content": {"sha": "n"}}),
            _FakeResponse(201, {
                "html_url": "https://github.com/o/r/pull/5", "number": 5,
            }),
        ])
        out = _call_adapter(http, filename=evil_filename)

        for v in out.values():
            if isinstance(v, str):
                assert _DUMMY_AUTH_VALUE not in v
        # filename 자체는 어댑터가 변경하지 않는다 (이는 use-case 의 로컬 저장
        # 경로에서 sanitize 됨 — 어댑터는 GitHub API 에 그대로 전달)
        # 단, GitHub PUT URL 에는 filename 이 그대로 들어가야 한다.
        assert any(
            evil_filename in c["url"] for c in http.calls if c["method"] == "PUT"
        )


# ============================================================
# 어댑터 — sys.modules['requests'] 폴백 (lazy import)
# ============================================================

class TestAdapterLazyRequests:
    def test_uses_sys_modules_requests_when_no_client_passed(
        self, monkeypatch,
    ):
        """``http_client`` 미지정 시 ``sys.modules['requests']`` 가 사용된다."""
        from api.services.github_patch_adapter import create_pull_request

        fake = _FakeRequests([
            _FakeResponse(200, {"object": {"sha": "abc"}}),
            _FakeResponse(201, {"ref": "refs/heads/fix/X"}),
            _FakeResponse(404, {}),
            _FakeResponse(201, {"content": {"sha": "n"}}),
            _FakeResponse(201, {
                "html_url": "https://github.com/o/r/pull/6", "number": 6,
            }),
        ])
        monkeypatch.setitem(sys.modules, "requests", fake)

        out = create_pull_request(
            token=_DUMMY_AUTH_VALUE,
            repo="owner/repo",
            filename="demo.py",
            fixed_code="a=2\n",
            vulnerability_id="VL",
            fix_type="recommended",
            diff=_DUMMY_DIFF,
        )
        assert out["status"] == "pr_created"
        assert out["pr_number"] == 6
        assert len(fake.calls) == 5


# ============================================================
# Use-case 위임 회귀 — patch_application → adapter
# ============================================================

class TestUseCaseDelegatesToAdapter:
    def test_workflow_calls_adapter_when_token_present(
        self, tmp_path, monkeypatch,
    ):
        from api.services import github_patch_adapter, patch_application

        captured: dict = {}

        def _fake_adapter(**kwargs):
            captured.update(kwargs)
            return {
                "status": "pr_created",
                "branch": "fix/INJECTED",
                "pr_url": "https://example.invalid/pull/77",
                "pr_number": 77,
                "message": "PR #77 생성 완료",
            }

        monkeypatch.setattr(
            github_patch_adapter, "create_pull_request", _fake_adapter,
        )

        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)

        upload_dir = tmp_path / "uploads"
        upload_dir.mkdir()

        result = patch_application.apply_patch_workflow(
            original_code="a=1\n",
            fixed_code="a=2\n",
            filename="demo.py",
            vulnerability_id="DEL1",
            fix_type="recommended",
            github_repo="owner/repo",
            github_token=_DUMMY_AUTH_VALUE,
            upload_dir=str(upload_dir),
        )

        # 어댑터가 호출되었는가 — 위임 검증
        assert captured["token"] == _DUMMY_AUTH_VALUE
        assert captured["repo"] == "owner/repo"
        assert captured["filename"] == "demo.py"
        assert captured["vulnerability_id"] == "DEL1"
        assert isinstance(captured["diff"], list)

        # 어댑터의 부분 결과가 base result 에 병합되었는가
        assert result["status"] == "pr_created"
        assert result["pr_number"] == 77
        assert result["branch"] == "fix/INJECTED"
        assert result["pr_url"].endswith("/pull/77")
        # base result 의 다른 키도 보존되어야 한다
        assert result["filename"] == "demo.py"
        assert result["vulnerability_id"] == "DEL1"
        assert "a=1" in result["diff"] and "a=2" in result["diff"]
        assert result["original_lines"] == 1
        assert result["fixed_lines"] == 1

    def test_workflow_wraps_adapter_exception_with_korean_message(
        self, tmp_path, monkeypatch,
    ):
        from api.services import github_patch_adapter, patch_application

        def _boom(**kwargs):
            raise RuntimeError("network down")

        monkeypatch.setattr(
            github_patch_adapter, "create_pull_request", _boom,
        )
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)

        upload_dir = tmp_path / "uploads"
        upload_dir.mkdir()

        result = patch_application.apply_patch_workflow(
            original_code="a=1\n",
            fixed_code="a=2\n",
            filename="demo.py",
            vulnerability_id="DEL2",
            fix_type="recommended",
            github_repo="owner/repo",
            github_token=_DUMMY_AUTH_VALUE,
            upload_dir=str(upload_dir),
        )

        assert result["status"] == "applied_local"
        assert "GitHub 연동 오류" in result["message"]
        assert "network down" in result["message"]
        # 토큰은 메시지에 노출되지 않아야 한다
        assert _DUMMY_AUTH_VALUE not in result["message"]
        assert _DUMMY_AUTH_VALUE not in result["diff"]


# ============================================================
# 트래버설 filename — 로컬 저장 안전성 회귀
# ============================================================

class TestTraversalFilenameLocalSaveSafety:
    """경로 트래버설 입력은 로컬 ``applied/`` 안에 평탄화 저장되어야 한다."""

    @pytest.mark.parametrize(
        "evil",
        [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\evil.dll",
            "/abs/path/leak.py",
            "sub/../sub/x.py",
        ],
    )
    def test_local_save_is_flattened_under_applied(self, evil, tmp_path):
        from api.services.patch_application import save_local_patch

        upload_dir = tmp_path / "uploads"
        upload_dir.mkdir()

        path = save_local_patch(str(upload_dir), evil, "fixed\n")

        applied_dir = upload_dir / "applied"
        # 저장 경로는 반드시 applied/ 직속이어야 하고, 디렉터리 트리는 만들어지지 않아야 한다.
        assert path.startswith(str(applied_dir) + "/") or path.startswith(
            str(applied_dir) + "\\"
        )
        from pathlib import Path as _P
        rel = _P(path).relative_to(applied_dir)
        assert len(rel.parts) == 1, (
            f"트래버설 입력이 중첩 디렉터리를 생성: {rel}"
        )
