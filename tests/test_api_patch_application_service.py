"""패치 적용 서비스 모듈 단위 테스트 (tests/test_api_patch_application_service.py).

Wave 2-L: ``api/routers/patch.py`` 에서 비즈니스 로직을 분리한
``api.services.patch_application`` 의 순수 헬퍼와 워크플로 함수에 대한
단위 테스트.

- 서비스 모듈은 ``api.server`` 를 직접 import 하지 않아야 한다.
- 헬퍼는 FastAPI/Pydantic 의존 없이 순수 함수로 호출 가능해야 한다.
- 워크플로는 ``requests`` 를 모듈 레벨에서 import 하지 않고, 호출 시점에
  ``sys.modules['requests']`` 를 통해 lazy 하게 사용해야 한다.
"""

from __future__ import annotations

import os
import sys

import pytest


# ============================================================
# Import surface
# ============================================================

class TestServiceImportSurface:
    def test_service_module_does_not_import_api_server(self):
        import ast
        import inspect

        from api.services import patch_application as svc

        tree = ast.parse(inspect.getsource(svc))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name != "api.server", "api.server 직접 import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "api.server", "from api.server import 금지"

    def test_service_module_does_not_import_requests_at_top_level(self):
        """`requests` 는 워크플로 호출 시점에만 lazy 하게 사용해야 한다."""
        import ast
        import inspect

        from api.services import patch_application as svc

        tree = ast.parse(inspect.getsource(svc))
        for node in tree.body:  # 모듈 최상위 import 만 검사
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name != "requests", "최상위에서 requests import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "requests", "최상위에서 requests import 금지"


# ============================================================
# 순수 헬퍼
# ============================================================

class TestSanitizeFilename:
    def test_forward_slash_replaced(self):
        from api.services.patch_application import sanitize_filename

        assert sanitize_filename("src/sub/dir/evil.py") == "src_sub_dir_evil.py"

    def test_backslash_replaced(self):
        from api.services.patch_application import sanitize_filename

        assert sanitize_filename("win\\path\\file.py") == "win_path_file.py"

    def test_plain_filename_unchanged(self):
        from api.services.patch_application import sanitize_filename

        assert sanitize_filename("demo.py") == "demo.py"


class TestBuildUnifiedDiff:
    def test_diff_includes_both_versions(self):
        from api.services.patch_application import build_unified_diff

        diff = build_unified_diff("a=1\n", "a=2\n", "demo.py")
        assert isinstance(diff, list)
        joined = "\n".join(diff)
        assert "a=1" in joined
        assert "a=2" in joined
        # unified diff 헤더 포맷
        assert any(line.startswith("---") and "demo.py" in line for line in diff)
        assert any(line.startswith("+++") and "demo.py" in line for line in diff)


class TestSaveLocalPatch:
    def test_saves_under_applied_subdir(self, tmp_path):
        from api.services.patch_application import save_local_patch

        upload_dir = str(tmp_path / "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        path = save_local_patch(upload_dir, "demo.py", "fixed content\n")

        expected = os.path.join(upload_dir, "applied", "demo.py")
        assert path == expected
        assert os.path.exists(expected)
        with open(expected, "r", encoding="utf-8") as f:
            assert f.read() == "fixed content\n"

    def test_sanitizes_path_separators(self, tmp_path):
        from api.services.patch_application import save_local_patch

        upload_dir = str(tmp_path / "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        path = save_local_patch(upload_dir, "src/sub/x.py", "ok\n")

        flat = os.path.join(upload_dir, "applied", "src_sub_x.py")
        assert path == flat
        assert os.path.exists(flat)
        # 디렉터리 트리는 만들지 않아야 함
        nested = os.path.join(upload_dir, "applied", "src", "sub", "x.py")
        assert not os.path.exists(nested)


# ============================================================
# 워크플로 — 로컬 폴백 / GitHub 모킹
# ============================================================

class _FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text or ""

    def json(self):
        return self._payload


class _FakeRequests:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def _next(self):
        return self._responses.pop(0)

    def _record(self, method, url, kwargs):
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


@pytest.fixture
def no_env_github(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)


class TestApplyPatchWorkflowLocal:
    def test_local_fallback_when_no_token(self, tmp_path, no_env_github):
        from api.services.patch_application import apply_patch_workflow

        upload_dir = str(tmp_path / "uploads")
        os.makedirs(upload_dir, exist_ok=True)

        result = apply_patch_workflow(
            original_code="a=1\n",
            fixed_code="a=2\n",
            filename="demo.py",
            vulnerability_id="B001",
            fix_type="recommended",
            github_repo="",
            github_token="",
            upload_dir=upload_dir,
        )

        assert result["status"] == "applied_local"
        assert result["pr_url"] is None
        assert result["branch"] is None
        assert result["original_lines"] == 1
        assert result["fixed_lines"] == 1
        assert "GITHUB_TOKEN" in result["message"]
        assert "a=1" in result["diff"]
        assert "a=2" in result["diff"]
        assert os.path.exists(os.path.join(upload_dir, "applied", "demo.py"))


class TestApplyPatchWorkflowGitHub:
    def test_pr_created_with_request_token(self, tmp_path, monkeypatch, no_env_github):
        from api.services.patch_application import apply_patch_workflow

        upload_dir = str(tmp_path / "uploads")
        os.makedirs(upload_dir, exist_ok=True)

        responses = [
            _FakeResponse(200, {"object": {"sha": "deadbeefshamain"}}),
            _FakeResponse(201, {"ref": "refs/heads/fix/X"}),
            _FakeResponse(404, {}),
            _FakeResponse(201, {"content": {"sha": "newsha"}}),
            _FakeResponse(201, {
                "html_url": "https://github.com/owner/repo/pull/42",
                "number": 42,
            }),
        ]
        fake = _FakeRequests(responses)
        monkeypatch.setitem(sys.modules, "requests", fake)

        token = "ghp_DUMMY_TOKEN"
        result = apply_patch_workflow(
            original_code="a=1\n",
            fixed_code="a=2\n",
            filename="demo.py",
            vulnerability_id="B100",
            fix_type="recommended",
            github_repo="owner/repo",
            github_token=token,
            upload_dir=upload_dir,
        )

        assert result["status"] == "pr_created"
        assert result["pr_url"] == "https://github.com/owner/repo/pull/42"
        assert result["pr_number"] == 42
        assert result["branch"].startswith("fix/B100_")
        # 토큰이 응답 어디에도 노출되지 않아야 함
        for v in (result.get("message", ""), result.get("diff", "")):
            assert token not in v
        assert len(fake.calls) == 5
