"""패치 적용 라우터 테스트 (tests/test_api_apply_patch_router.py).

Wave 2-F: POST /api/apply-patch 의 동작과 응답 셰이프를 보존하기 위한
스모크/회귀 테스트. 외부 GitHub API 호출은 라우터 모듈의 lazy import 된
requests 객체를 monkeypatch 하여 절대 실제 네트워크가 발생하지 않도록 한다.

또한 서비스 부트스트랩 스모크(POST /api/apply-patch 로컬 폴백) 도 포함한다.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from api.routers import patch as patch_router
from api.server import app


_AUTH_HEADERS = {"X-API-Key": "test-api-key"}
client = TestClient(app)


# ============================================================
# 가짜 requests / 응답
# ============================================================

class _FakeResponse:
    """requests.Response 의 테스트 더블."""

    def __init__(self, status_code: int = 200, payload: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text or ""

    def json(self) -> dict:
        return self._payload


class _FakeRequests:
    """라우터의 lazy import 된 requests 모듈을 가로채는 더블.

    호출 순서/메서드/URL 을 기록하여 GitHub API 호출 시퀀스가 기대대로
    이루어지는지 검증한다. 실제 네트워크는 절대 발생하지 않는다.
    """

    def __init__(self, responses: list[_FakeResponse]):
        self._responses = list(responses)
        self.calls: list[dict] = []

    def _next(self) -> _FakeResponse:
        if not self._responses:
            raise AssertionError("FakeRequests: 예상보다 많은 호출이 발생")
        return self._responses.pop(0)

    def _record(self, method: str, url: str, kwargs: dict) -> None:
        self.calls.append({
            "method": method,
            "url": url,
            "headers": kwargs.get("headers"),
            "json": kwargs.get("json"),
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
def isolated_upload_dir(tmp_path, monkeypatch):
    """patch 라우터의 UPLOAD_DIR 을 tmp_path 로 격리."""
    target = tmp_path / "uploads"
    target.mkdir()
    monkeypatch.setattr(patch_router, "UPLOAD_DIR", str(target))
    return str(target)


@pytest.fixture
def no_env_github(monkeypatch):
    """환경변수 GITHUB_TOKEN/REPOSITORY 의 영향을 차단."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)


def _install_fake_requests(monkeypatch, responses: list[_FakeResponse]) -> _FakeRequests:
    """라우터가 함수 내부에서 import 하는 requests 모듈 자체를 가짜로 교체.

    `import requests as http_requests` 는 sys.modules['requests'] 를 참조하므로
    sys.modules 를 패치하여 가짜 객체로 대체한다.
    """
    import sys
    fake = _FakeRequests(responses)
    monkeypatch.setitem(sys.modules, "requests", fake)
    return fake


# ============================================================
# 인증 보호
# ============================================================

class TestApplyPatchAuth:
    def test_post_requires_auth(self):
        r = client.post(
            "/api/apply-patch",
            json={
                "original_code": "a=1\n",
                "fixed_code": "a=2\n",
                "filename": "demo.py",
                "vulnerability_id": "B001",
            },
        )
        assert r.status_code in (401, 403)


# ============================================================
# 로컬 폴백 (토큰/레포 미설정)
# ============================================================

class TestApplyPatchLocalFallback:
    REQUIRED_KEYS = {
        "status", "filename", "vulnerability_id", "fix_type",
        "diff", "original_lines", "fixed_lines",
        "pr_url", "branch", "message",
    }

    def test_local_fallback_response_shape(self, isolated_upload_dir, no_env_github):
        payload = {
            "original_code": "a=1\n",
            "fixed_code": "a=2\n",
            "filename": "demo.py",
            "vulnerability_id": "B001",
            "fix_type": "recommended",
        }
        r = client.post("/api/apply-patch", headers=_AUTH_HEADERS, json=payload)
        assert r.status_code == 200, r.text

        data = r.json()
        assert self.REQUIRED_KEYS <= set(data.keys())
        assert data["status"] == "applied_local"
        assert data["pr_url"] is None
        assert data["branch"] is None
        assert data["filename"] == "demo.py"
        assert data["vulnerability_id"] == "B001"
        assert data["fix_type"] == "recommended"
        assert data["original_lines"] == 1
        assert data["fixed_lines"] == 1
        assert "GITHUB_TOKEN" in data["message"]
        # diff 는 통합 unified diff 가 와야 한다
        assert "a=1" in data["diff"]
        assert "a=2" in data["diff"]

    def test_local_file_written_to_upload_dir(self, isolated_upload_dir, no_env_github):
        payload = {
            "original_code": "x=1\n",
            "fixed_code": "x=2\n",
            "filename": "demo.py",
            "vulnerability_id": "B002",
        }
        r = client.post("/api/apply-patch", headers=_AUTH_HEADERS, json=payload)
        assert r.status_code == 200

        applied = os.path.join(isolated_upload_dir, "applied", "demo.py")
        assert os.path.exists(applied)
        with open(applied, "r", encoding="utf-8") as f:
            assert f.read() == "x=2\n"

    def test_filename_path_separators_sanitized(self, isolated_upload_dir, no_env_github):
        """파일명에 / 또는 \\ 가 포함되어도 로컬 저장 경로는 안전하게 평탄화."""
        payload = {
            "original_code": "old\n",
            "fixed_code": "new\n",
            "filename": "src/sub/dir/evil.py",
            "vulnerability_id": "B003",
        }
        r = client.post("/api/apply-patch", headers=_AUTH_HEADERS, json=payload)
        assert r.status_code == 200

        # 디렉터리 구조가 만들어지지 않고 평탄화된 파일명으로 저장되어야 한다
        applied_dir = os.path.join(isolated_upload_dir, "applied")
        flat = os.path.join(applied_dir, "src_sub_dir_evil.py")
        nested = os.path.join(applied_dir, "src", "sub", "dir", "evil.py")
        assert os.path.exists(flat)
        assert not os.path.exists(nested)
        # 응답 셰이프상 filename 은 원본을 보존해야 한다
        assert r.json()["filename"] == "src/sub/dir/evil.py"

    def test_backslash_filename_sanitized(self, isolated_upload_dir, no_env_github):
        payload = {
            "original_code": "old\n",
            "fixed_code": "new\n",
            "filename": "win\\path\\file.py",
            "vulnerability_id": "B003b",
        }
        r = client.post("/api/apply-patch", headers=_AUTH_HEADERS, json=payload)
        assert r.status_code == 200
        flat = os.path.join(isolated_upload_dir, "applied", "win_path_file.py")
        assert os.path.exists(flat)


# ============================================================
# GitHub 성공 경로 (모킹)
# ============================================================

class TestApplyPatchGitHubSuccess:
    def test_success_flow_with_token_in_request(
        self, monkeypatch, isolated_upload_dir, no_env_github,
    ):
        """요청에 token/repo 가 포함된 성공 경로 — 호출 순서/헤더/응답 검증."""
        responses = [
            # 1) GET ref/heads/main
            _FakeResponse(200, {"object": {"sha": "deadbeefshamain"}}),
            # 2) POST git/refs (브랜치 생성)
            _FakeResponse(201, {"ref": "refs/heads/fix/X"}),
            # 3) GET contents/{file}?ref=branch — 신규 파일 (404)
            _FakeResponse(404, {}),
            # 4) PUT contents/{file} — 커밋 성공
            _FakeResponse(201, {"content": {"sha": "newsha"}}),
            # 5) POST pulls — PR 생성
            _FakeResponse(201, {
                "html_url": "https://github.com/owner/repo/pull/42",
                "number": 42,
            }),
        ]
        fake = _install_fake_requests(monkeypatch, responses)

        token_value = "ghp_TESTONLY_DUMMY_TOKEN_xxxxx"
        payload = {
            "original_code": "a=1\n",
            "fixed_code": "a=2\n",
            "filename": "demo.py",
            "vulnerability_id": "B100",
            "fix_type": "recommended",
            "github_repo": "owner/repo",
            "github_token": token_value,
        }
        r = client.post("/api/apply-patch", headers=_AUTH_HEADERS, json=payload)
        assert r.status_code == 200, r.text
        data = r.json()

        assert data["status"] == "pr_created"
        assert data["pr_url"] == "https://github.com/owner/repo/pull/42"
        assert data["pr_number"] == 42
        assert data["branch"].startswith("fix/B100_")
        assert "PR #42" in data["message"]

        # 토큰이 응답/메시지/diff 어디에도 노출되지 않아야 한다
        assert token_value not in r.text
        assert token_value not in data.get("message", "")
        assert token_value not in data.get("diff", "")

        # 호출 순서/메서드/URL 검증 (timestamp 가 변동되므로 prefix 검사)
        assert len(fake.calls) == 5

        c0 = fake.calls[0]
        assert c0["method"] == "GET"
        assert c0["url"].endswith("/repos/owner/repo/git/ref/heads/main")
        # 인증 헤더는 존재하지만 토큰 자체를 응답에 노출하지 않아야 한다
        assert c0["headers"] is not None
        assert "Authorization" in c0["headers"]
        assert c0["headers"]["Authorization"].startswith("Bearer ")

        c1 = fake.calls[1]
        assert c1["method"] == "POST"
        assert c1["url"].endswith("/repos/owner/repo/git/refs")
        assert c1["json"]["ref"].startswith("refs/heads/fix/B100_")
        assert c1["json"]["sha"] == "deadbeefshamain"

        c2 = fake.calls[2]
        assert c2["method"] == "GET"
        assert "/repos/owner/repo/contents/demo.py?ref=fix/B100_" in c2["url"]

        c3 = fake.calls[3]
        assert c3["method"] == "PUT"
        assert c3["url"].endswith("/repos/owner/repo/contents/demo.py")
        # 새 파일이므로 sha 키는 포함되지 않아야 함
        assert "sha" not in c3["json"]
        assert c3["json"]["branch"].startswith("fix/B100_")

        c4 = fake.calls[4]
        assert c4["method"] == "POST"
        assert c4["url"].endswith("/repos/owner/repo/pulls")
        assert c4["json"]["base"] == "main"
        assert c4["json"]["head"].startswith("fix/B100_")

    def test_success_flow_with_env_token(
        self, monkeypatch, isolated_upload_dir,
    ):
        """env 의 GITHUB_TOKEN/REPOSITORY 가 폴백으로 사용되는 경로."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_env_only_dummy")
        monkeypatch.setenv("GITHUB_REPOSITORY", "envowner/envrepo")

        responses = [
            _FakeResponse(200, {"object": {"sha": "envsha"}}),
            _FakeResponse(201, {}),
            _FakeResponse(200, {"sha": "existing-file-sha"}),  # 파일이 존재
            _FakeResponse(200, {"content": {"sha": "newsha"}}),  # PUT 성공 (200)
            _FakeResponse(200, {
                "html_url": "https://github.com/envowner/envrepo/pull/7",
                "number": 7,
            }),
        ]
        fake = _install_fake_requests(monkeypatch, responses)

        payload = {
            "original_code": "old\n",
            "fixed_code": "new\n",
            "filename": "envfile.py",
            "vulnerability_id": "B200",
        }
        r = client.post("/api/apply-patch", headers=_AUTH_HEADERS, json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "pr_created"
        assert data["pr_url"].endswith("/pull/7")

        # 첫 호출 URL 이 env 의 repo 를 사용했는지
        assert "/repos/envowner/envrepo/" in fake.calls[0]["url"]
        # 기존 파일 sha 가 있으면 PUT 시 sha 가 포함돼야 함
        assert fake.calls[3]["json"].get("sha") == "existing-file-sha"


# ============================================================
# GitHub 실패 경로
# ============================================================

class TestApplyPatchGitHubFailure:
    def test_main_ref_failure_preserves_local_save(
        self, monkeypatch, isolated_upload_dir, no_env_github,
    ):
        """main ref 조회 실패 시에도 로컬 저장/diff 는 보존되어야 한다."""
        responses = [_FakeResponse(404, {"message": "Not Found"})]
        _install_fake_requests(monkeypatch, responses)

        payload = {
            "original_code": "a=1\n",
            "fixed_code": "a=2\n",
            "filename": "demo.py",
            "vulnerability_id": "B300",
            "github_repo": "owner/repo",
            "github_token": "ghp_dummy",
        }
        r = client.post("/api/apply-patch", headers=_AUTH_HEADERS, json=payload)
        assert r.status_code == 200
        data = r.json()

        # 상태는 applied_local 로 유지 + diff 는 제공
        assert data["status"] == "applied_local"
        assert "main 브랜치 조회 실패" in data["message"]
        assert "a=1" in data["diff"] and "a=2" in data["diff"]

        # 로컬 저장도 그대로 수행되었는지
        applied = os.path.join(isolated_upload_dir, "applied", "demo.py")
        assert os.path.exists(applied)

    def test_network_exception_does_not_crash(
        self, monkeypatch, isolated_upload_dir, no_env_github,
    ):
        """requests 가 네트워크 예외를 던져도 라우터는 200 + 메시지로 응답."""

        class _BoomRequests:
            def get(self, url, **kwargs):
                raise RuntimeError("network down")

            def post(self, url, **kwargs):
                raise RuntimeError("network down")

            def put(self, url, **kwargs):
                raise RuntimeError("network down")

        import sys
        monkeypatch.setitem(sys.modules, "requests", _BoomRequests())

        payload = {
            "original_code": "a=1\n",
            "fixed_code": "a=2\n",
            "filename": "demo.py",
            "vulnerability_id": "B301",
            "github_repo": "owner/repo",
            "github_token": "ghp_dummy",
        }
        r = client.post("/api/apply-patch", headers=_AUTH_HEADERS, json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "applied_local"
        assert "GitHub 연동 오류" in data["message"]
        # diff/로컬 저장 모두 보존
        assert "a=2" in data["diff"]
        assert os.path.exists(
            os.path.join(isolated_upload_dir, "applied", "demo.py"),
        )


# ============================================================
# 라우터 임포트 회귀 — api.server 미의존
# ============================================================

class TestRouterImportSurface:
    def test_module_does_not_import_api_server(self):
        import ast
        import inspect

        import api.routers.patch as mod

        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name != "api.server", "api.server 직접 import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "api.server", "from api.server import 금지"

    def test_request_model_lives_in_router(self):
        assert hasattr(patch_router, "ApplyPatchRequest")


# ============================================================
# Wave 2-L: 라우터는 비즈니스 로직을 서비스 모듈에 위임해야 한다
# ============================================================

class TestRouterDelegatesToService:
    """라우터 본문에서 GitHub 워크플로/HTTP/base64 직접 호출이 사라져야 한다.

    엔드포인트 함수의 소스 본문을 AST 로 검사해 다음을 금지한다:
      - ``requests.get``/``post``/``put`` 직접 호출
      - ``base64.b64encode`` 직접 호출
      - GitHub API URL 문자열 직접 구성 (``api.github.com`` 또는 ``/git/refs``)
    """

    def _endpoint_source(self) -> str:
        import ast
        import inspect

        import api.routers.patch as mod

        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "apply_patch":
                return ast.unparse(node)
        raise AssertionError("apply_patch 엔드포인트를 찾을 수 없음")

    def test_endpoint_does_not_call_requests_methods(self):
        src = self._endpoint_source()
        assert "http_requests.get" not in src, "requests.get 직접 호출 금지"
        assert "http_requests.post" not in src, "requests.post 직접 호출 금지"
        assert "http_requests.put" not in src, "requests.put 직접 호출 금지"

    def test_endpoint_does_not_call_base64(self):
        src = self._endpoint_source()
        assert "b64encode" not in src, "base64.b64encode 직접 호출 금지"

    def test_endpoint_does_not_construct_github_urls(self):
        src = self._endpoint_source()
        assert "api.github.com" not in src, "GitHub URL 직접 구성 금지"
        assert "/git/refs" not in src, "GitHub refs URL 직접 구성 금지"

    def test_endpoint_does_not_run_difflib_directly(self):
        src = self._endpoint_source()
        assert "difflib.unified_diff" not in src, (
            "difflib.unified_diff 직접 호출 대신 서비스 헬퍼를 호출해야 함"
        )

    def test_service_module_exists(self):
        from api.services import patch_application as svc

        # 서비스 모듈은 핵심 워크플로 진입점을 노출해야 한다
        assert callable(getattr(svc, "apply_patch_workflow", None))


# ============================================================
# 서비스 부트스트랩 스모크 — POST /api/apply-patch 로컬 폴백
# ============================================================

class TestServiceBootstrap:
    def test_apply_patch_local_fallback_smoke(
        self, isolated_upload_dir, no_env_github,
    ):
        """app 임포트 + POST /api/apply-patch 로컬 폴백 200 — 라우터 분리 회귀 차단."""
        r = client.post(
            "/api/apply-patch",
            headers=_AUTH_HEADERS,
            json={
                "original_code": "a=1\n",
                "fixed_code": "a=2\n",
                "filename": "smoke.py",
                "vulnerability_id": "SMK001",
                "fix_type": "recommended",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "applied_local"
        assert data["pr_url"] is None
