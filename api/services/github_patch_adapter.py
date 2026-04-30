"""GitHub 패치 어댑터 (api/services/github_patch_adapter.py).

Wave 3-E: ``api/services/patch_application.py`` 에서 GitHub HTTP 인프라
호출(refs/contents/commits/pulls)을 분리한 어댑터. use-case 서비스는
diff 생성, 로컬 저장, 응답 셰이프 조립만 담당하고, 본 모듈은 GitHub
REST API 시퀀스를 책임진다 (Clean Architecture: 인프라 어댑터).

설계 원칙:
  - FastAPI / Pydantic / ``api.server`` 를 import 하지 않는다.
  - ``requests`` 는 ``create_pull_request`` 호출 시점에 lazy import 한다.
    테스트는 ``sys.modules['requests']`` 를 가짜 객체로 교체하거나,
    ``http_client`` 인자에 직접 더블을 주입해 네트워크를 차단할 수 있다.
  - GitHub 토큰은 응답 dict / 메시지 어디에도 노출하지 않는다 (Authorization
    헤더에만 사용).
  - 호출 결과 키와 한국어 메시지는 use-case 회귀를 막기 위해 기존 흐름과
    동일하게 유지한다.
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any, List, Optional


def _lazy_requests() -> Any:
    """``requests`` 모듈을 호출 시점에 가져온다.

    테스트가 ``sys.modules['requests']`` 를 가짜로 교체했다면 그 가짜가
    그대로 반환된다 — 실제 네트워크는 절대 발생하지 않는다.
    """
    import requests as http_requests
    return http_requests


def _branch_name(vulnerability_id: str, now: Optional[datetime] = None) -> str:
    ts = (now or datetime.now()).strftime("%Y%m%d_%H%M%S")
    return f"fix/{vulnerability_id}_{ts}"


def _build_pr_body(
    *, vulnerability_id: str, fix_type: str, filename: str, diff: List[str],
) -> str:
    return (
        "## 🤖 Dallo AI 보안 수정안\n\n"
        f"**취약점**: `{vulnerability_id}`\n"
        f"**수정 유형**: {fix_type}\n"
        f"**파일**: `{filename}`\n\n"
        "### Diff\n"
        "```diff\n"
        f"{chr(10).join(diff)}\n"
        "```\n\n"
        "---\n"
        "*🛡️ Dallo DevSecOps — AI 자동 수정안*\n"
    )


def create_pull_request(
    *,
    token: str,
    repo: str,
    filename: str,
    fixed_code: str,
    vulnerability_id: str,
    fix_type: str,
    diff: List[str],
    http_client: Any = None,
    now: Optional[datetime] = None,
) -> dict:
    """GitHub 브랜치 + 커밋 + PR 생성을 수행하고 부분 결과 dict 를 반환한다.

    반환 dict 는 use-case 의 base result 에 ``update()`` 되어 최종 응답을
    구성한다. 호출 결과에 따라 다음 키를 포함한다:

    - 성공 (PR 생성): ``status="pr_created"``, ``branch``, ``pr_url``,
      ``pr_number``, ``message``.
    - 커밋은 됐지만 PR 만 실패: ``status="committed"``, ``branch``, ``pr_url=None``,
      ``message``.
    - 그 외 GitHub 호출 실패: ``status="applied_local"``, ``branch=None``,
      ``pr_url=None``, ``message`` (한국어 실패 메시지).

    네트워크 예외는 호출자가 감싸도록 그대로 전파한다 (use-case 가
    "GitHub 연동 오류: ..." 메시지로 변환).
    """
    http = http_client or _lazy_requests()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    api_base = f"https://api.github.com/repos/{repo}"

    ref_resp = http.get(
        f"{api_base}/git/ref/heads/main", headers=headers, timeout=10,
    )
    if ref_resp.status_code != 200:
        return {
            "status": "applied_local",
            "branch": None,
            "pr_url": None,
            "message": f"main 브랜치 조회 실패: {ref_resp.status_code}",
        }
    main_sha = ref_resp.json()["object"]["sha"]

    branch_name = _branch_name(vulnerability_id, now=now)
    create_ref = http.post(
        f"{api_base}/git/refs",
        headers=headers,
        json={"ref": f"refs/heads/{branch_name}", "sha": main_sha},
        timeout=10,
    )
    if create_ref.status_code not in (200, 201):
        return {
            "status": "applied_local",
            "branch": None,
            "pr_url": None,
            "message": f"브랜치 생성 실패: {create_ref.status_code}",
        }

    file_resp = http.get(
        f"{api_base}/contents/{filename}?ref={branch_name}",
        headers=headers, timeout=10,
    )
    file_sha = (
        file_resp.json().get("sha") if file_resp.status_code == 200 else None
    )

    content_b64 = base64.b64encode(fixed_code.encode("utf-8")).decode("utf-8")
    commit_data = {
        "message": (
            f"fix: {vulnerability_id} 보안 취약점 수정 ({fix_type})\n\n"
            "Dallo AI 자동 수정안 적용"
        ),
        "content": content_b64,
        "branch": branch_name,
    }
    if file_sha:
        commit_data["sha"] = file_sha

    commit_resp = http.put(
        f"{api_base}/contents/{filename}",
        headers=headers,
        json=commit_data,
        timeout=10,
    )
    if commit_resp.status_code not in (200, 201):
        return {
            "status": "applied_local",
            "branch": None,
            "pr_url": None,
            "message": (
                f"커밋 실패: {commit_resp.status_code} {commit_resp.text[:200]}"
            ),
        }

    pr_body = _build_pr_body(
        vulnerability_id=vulnerability_id,
        fix_type=fix_type,
        filename=filename,
        diff=diff,
    )
    pr_resp = http.post(
        f"{api_base}/pulls",
        headers=headers,
        json={
            "title": f"🤖 fix: {vulnerability_id} 보안 취약점 수정",
            "head": branch_name,
            "base": "main",
            "body": pr_body,
        },
        timeout=10,
    )

    if pr_resp.status_code in (200, 201):
        pr_data = pr_resp.json()
        return {
            "status": "pr_created",
            "branch": branch_name,
            "pr_url": pr_data["html_url"],
            "pr_number": pr_data["number"],
            "message": f"PR #{pr_data['number']} 생성 완료",
        }
    return {
        "status": "committed",
        "branch": branch_name,
        "pr_url": None,
        "message": f"브랜치 커밋 완료, PR 생성 실패: {pr_resp.status_code}",
    }


__all__ = ["create_pull_request"]
