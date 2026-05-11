"""
GitHub API 연동 클라이언트 (Wave 4-R: fakeable HTTP seam 도입 — 여전히 휴면 모듈)

[상태]
- 본 모듈은 여전히 휴면(dormant) 상태이며, Dallo 운영 워크플로우/스크립트
  에서 active caller 는 0 건이다 (Wave 4-Q audit 시점 기준). 운영 PR
  코멘트 경로는 ``scripts/post_pr_comment.py`` → ``integrations/
  github_pr_comment_adapter.py`` 만 사용하며, 본 모듈을 import 하지 않는다.
- Wave 4-R 에서는 미래 활성화 시점을 안전하게 만들기 위해, 본 모듈이
  여러 wave 동안 deferred 상태로 안고 있던 “활성화 전 필요 작업” 중
  코드 차원의 항목을 적용했다. **운영 wiring (워크플로우, 스크립트,
  GitHub Actions 이벤트 트리거) 은 의도적으로 도입하지 않는다.**

[Wave 4-R 에서 적용된 seam]
- top-level ``import requests`` 제거. 대신 ``_default_http_client()``
  헬퍼가 ``requests`` 모듈을 lazy import 한다.
- ``GitHubClient(..., http_client=None, timeout=30)`` — ``requests`` 와
  호환되는 ``get/post`` 시그니처 객체를 주입 가능. ``github_pr_comment_
  adapter`` 와 동일한 패턴이다.
- 모든 HTTP 호출에 explicit ``timeout=`` 키워드 인자 전달.
- 모든 public 메서드는 raw ``raise_for_status()`` 전파 대신 정규화된
  ``{"status": "ok"|"failed", "message": str, "data": ...}`` 를 반환한다.
- non-2xx 응답뿐 아니라 ``client.get`` / ``client.post`` 의 **transport
  단계 예외** (network down, DNS, SSL, ``ConnectionError`` 등) 도 동일
  정규화 dict 로 흡수된다. raw ``str(exc)`` 는 반환 메시지에 포함하지
  않고 안정적 한국어 메시지 (예: ``"[!] Check Run 생성 실패: transport
  error"``) 만 노출한다.
- 실패 메시지에는 status code 또는 transport 라벨만 노출하고 응답
  본문/토큰/raw 예외 메시지를 노출하지 않는다 (token 비누출 보장).
- ``create_check_run`` payload 는 GitHub Check Runs REST 모양
  (``name``, ``head_sha``, ``status``, ``output.{title,summary,text}``,
  optional ``conclusion``) 을 그대로 유지한다.

[보존 사유 / 미래 활성화]
- 본 모듈은 PR 메타데이터/변경 파일 조회, 라인 단위 review 코멘트, Check
  Run 생성, GitHub Actions 이벤트 파서 surface 를 향후 사용 가능 자산으로
  보관한다. 본 wave 에서는 워크플로우/스크립트/Actions 트리거 어디에서도
  본 모듈을 호출하지 않는다 — wiring 은 실 consumer 가 확정될 때 별도
  wave 에서 도입한다.

[활성화 전 남은 작업]
- 운영 워크플로우/스크립트로의 실제 wiring (예: ``scripts/post_check_run.py``
  + ``.github/workflows/*`` 에서 본 모듈을 호출).
- 통합 회귀 테스트 (운영 호출 경로가 정해지는 시점).

본 docstring 의 정책 ("신규 코드에서 직접 import 하지 마십시오") 은
Wave 4-R 이후에도 유효하다. 본 wave 의 변화는 “HTTP 경계가 fakeable
하다” 는 것뿐이며, 모듈 자체는 여전히 미사용 자산이다.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Optional


def _default_http_client():
    """``requests`` 모듈을 lazy import 해 반환한다.

    top-level import 를 피해 (1) 본 모듈을 import 만 하는 단위 테스트가
    실 네트워크 의존을 끌어오지 않도록 하고, (2) 테스트에서 본 헬퍼를
    monkeypatch 해 fake client 로 교체할 수 있게 한다.
    """
    import requests

    return requests


@dataclass
class PRInfo:
    """Pull Request 정보."""

    owner: str
    repo: str
    pr_number: int
    head_sha: str
    base_branch: str
    head_branch: str
    title: str
    changed_files: list[str]


def _status_code(resp: Any) -> Any:
    return getattr(resp, "status_code", None)


def _safe_json(resp: Any) -> Any:
    """응답 body 의 JSON 디코드 시 예외를 흡수해 ``None`` 을 반환한다."""
    try:
        return resp.json()
    except Exception:
        return None


def _failed(message: str) -> dict:
    return {"status": "failed", "message": message, "data": None}


def _ok(message: str, data: Any) -> dict:
    return {"status": "ok", "message": message, "data": data}


def _safe_call(call, transport_failure_message: str):
    """HTTP 호출을 try 로 감싸 transport 단계 예외를 정규화 dict 로 흡수한다.

    ``call`` 은 zero-arg callable (``lambda: client.get(...)`` 또는
    ``lambda: client.post(...)``) 이다. 정상 경로에서는 ``(resp, None)`` 을
    반환하고, 예외가 발생하면 raw ``str(exc)`` 를 노출하지 않는 안정적
    한국어 메시지를 가진 ``(None, _failed(...))`` 를 반환한다.

    raw 예외 메시지를 결과에 포함하지 않는 이유: GitHub 가 보낸 응답 본문
    유사 텍스트, ``Authorization`` 헤더로 흘러간 토큰, 자격 증명이 박힌
    URL, 프록시/디버그 텍스트가 transport 예외 메시지에 섞일 수 있고,
    그것이 호출 측의 stdout/로깅으로 새는 것을 차단해야 하기 때문이다.
    """
    try:
        return call(), None
    except Exception:
        return None, _failed(transport_failure_message)


class GitHubClient:
    """GitHub API 클라이언트 (휴면 모듈, fakeable HTTP seam).

    Parameters
    ----------
    token:
        Bearer 토큰. 미지정 시 ``GITHUB_TOKEN`` 환경 변수에서 읽는다.
    http_client:
        ``requests`` 와 호환되는 ``get(url, **kw)`` / ``post(url, **kw)``
        시그니처 객체. 미주입 시 ``_default_http_client()`` 가 lazy 로
        ``requests`` 모듈을 반환한다.
    timeout:
        모든 HTTP 호출에 적용될 ``timeout`` 초. 기본 30s.
    """

    BASE_URL = "https://api.github.com"

    def __init__(
        self,
        token: Optional[str] = None,
        *,
        http_client: Any = None,
        timeout: float = 30,
    ):
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self._http_client = http_client
        self._timeout = timeout
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _client(self) -> Any:
        if self._http_client is not None:
            return self._http_client
        return _default_http_client()

    def get_pr_info(self, owner: str, repo: str, pr_number: int) -> dict:
        """PR 기본 정보 + 변경 파일 목록을 조회한다.

        성공 시 ``{"status": "ok", "data": PRInfo(...)}``, 실패 시
        ``{"status": "failed", "message": "...<코드>...", "data": None}``.
        실패 메시지에는 status code 만 포함하고 응답 본문/토큰은 포함하지
        않는다.
        """
        client = self._client()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/pulls/{pr_number}"
        resp, transport_err = _safe_call(
            lambda: client.get(
                url, headers=self.headers, timeout=self._timeout
            ),
            "[!] PR 정보 조회 실패: transport error",
        )
        if transport_err is not None:
            return transport_err
        code = _status_code(resp)
        if code != 200:
            return _failed(f"[!] PR 정보 조회 실패: {code}")
        data = _safe_json(resp) or {}

        files_url = f"{url}/files"
        files_resp, files_transport_err = _safe_call(
            lambda: client.get(
                files_url, headers=self.headers, timeout=self._timeout
            ),
            "[!] PR 파일 조회 실패: transport error",
        )
        if files_transport_err is not None:
            return files_transport_err
        files_code = _status_code(files_resp)
        if files_code != 200:
            return _failed(f"[!] PR 파일 조회 실패: {files_code}")
        files_data = _safe_json(files_resp) or []
        changed_files = [
            f.get("filename")
            for f in files_data
            if isinstance(f, dict) and f.get("filename")
        ]

        head = data.get("head") or {}
        base = data.get("base") or {}
        pr_info = PRInfo(
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            head_sha=head.get("sha", ""),
            base_branch=base.get("ref", ""),
            head_branch=head.get("ref", ""),
            title=data.get("title", ""),
            changed_files=changed_files,
        )
        return _ok("[+] PR 정보 조회 완료", pr_info)

    def get_changed_python_files(
        self, owner: str, repo: str, pr_number: int
    ) -> dict:
        """PR 의 변경 파일 중 ``.py`` 만 추출한다."""
        result = self.get_pr_info(owner, repo, pr_number)
        if result.get("status") != "ok":
            return {
                "status": "failed",
                "message": result.get("message", "[!] PR 파일 조회 실패"),
                "data": [],
            }
        pr_info: PRInfo = result["data"]
        py_files = [f for f in pr_info.changed_files if f.endswith(".py")]
        return _ok("[+] PR Python 파일 추출 완료", py_files)

    def create_pr_comment(
        self, owner: str, repo: str, pr_number: int, body: str
    ) -> dict:
        """PR 본문에 일반 코멘트를 작성한다."""
        url = (
            f"{self.BASE_URL}/repos/{owner}/{repo}/issues/{pr_number}/comments"
        )
        client = self._client()
        resp, transport_err = _safe_call(
            lambda: client.post(
                url,
                headers=self.headers,
                json={"body": body},
                timeout=self._timeout,
            ),
            "[!] PR 코멘트 생성 실패: transport error",
        )
        if transport_err is not None:
            return transport_err
        code = _status_code(resp)
        if code == 201:
            return _ok("[+] PR 코멘트 생성 완료", _safe_json(resp))
        return _failed(f"[!] PR 코멘트 생성 실패: {code}")

    def create_review_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
        commit_id: str,
        path: str,
        line: int,
    ) -> dict:
        """PR 의 특정 코드 라인에 review 코멘트를 작성한다."""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/pulls/{pr_number}/comments"
        payload = {
            "body": body,
            "commit_id": commit_id,
            "path": path,
            "line": line,
        }
        client = self._client()
        resp, transport_err = _safe_call(
            lambda: client.post(
                url, headers=self.headers, json=payload, timeout=self._timeout
            ),
            "[!] PR 리뷰 코멘트 생성 실패: transport error",
        )
        if transport_err is not None:
            return transport_err
        code = _status_code(resp)
        if code == 201:
            return _ok("[+] PR 리뷰 코멘트 생성 완료", _safe_json(resp))
        return _failed(f"[!] PR 리뷰 코멘트 생성 실패: {code}")

    def create_check_run(
        self,
        owner: str,
        repo: str,
        head_sha: str,
        name: str,
        status: str,
        conclusion: Optional[str] = None,
        summary: str = "",
        text: str = "",
    ) -> dict:
        """GitHub Check Run 을 생성한다.

        payload 는 GitHub Check Runs REST 모양 (``name``, ``head_sha``,
        ``status``, ``output.{title,summary,text}``) 을 그대로 유지하며,
        ``conclusion`` 은 제공된 경우에만 포함된다.
        """
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/check-runs"
        payload: dict[str, Any] = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
            "output": {
                "title": name,
                "summary": summary,
                "text": text,
            },
        }
        if conclusion:
            payload["conclusion"] = conclusion

        client = self._client()
        resp, transport_err = _safe_call(
            lambda: client.post(
                url, headers=self.headers, json=payload, timeout=self._timeout
            ),
            "[!] Check Run 생성 실패: transport error",
        )
        if transport_err is not None:
            return transport_err
        code = _status_code(resp)
        if code in (200, 201):
            return _ok("[+] Check Run 생성 완료", _safe_json(resp))
        return _failed(f"[!] Check Run 생성 실패: {code}")

    @staticmethod
    def from_github_event() -> tuple[str, str, int]:
        """GitHub Actions 환경에서 (owner, repo, pr_number) 를 추출한다."""
        event_path = os.environ.get("GITHUB_EVENT_PATH", "")
        if not event_path or not os.path.exists(event_path):
            raise RuntimeError("GITHUB_EVENT_PATH가 설정되지 않았습니다.")

        with open(event_path, "r") as f:
            event = json.load(f)

        repo_full = os.environ.get("GITHUB_REPOSITORY", "")
        if "/" not in repo_full:
            raise RuntimeError("GITHUB_REPOSITORY 형식이 올바르지 않습니다.")

        owner, repo = repo_full.split("/", 1)
        pr_number = event.get("pull_request", {}).get("number")

        if not pr_number:
            raise RuntimeError("Pull Request 이벤트가 아닙니다.")

        return owner, repo, pr_number
