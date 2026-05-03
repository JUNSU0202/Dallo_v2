"""GitHub PR 코멘트 HTTP 어댑터 (integrations/github_pr_comment_adapter.py).

Wave 4-B: ``scripts/post_pr_comment.py::post_comment()`` 가 직접 호출하던
``requests.get/patch/post`` HTTP 경계를 infrastructure adapter 로 분리한다.
스크립트는 환경 변수 로딩과 한국어 stdout 출력에 집중하고, 본 모듈은
GitHub Issues 코멘트 REST API 호출 책임만 진다 (Clean Architecture: 외부
HTTP 어댑터).

설계 원칙:
  - 본 모듈은 ``requests`` 를 top-level 에서 import 하지 않는다. 실제 호출
    시점에 lazy import 하거나 호출자가 ``http_client`` 더블을 주입한다.
  - ``http_client`` 는 ``get(url, headers=...)``, ``patch(url, headers=...,
    json=...)``, ``post(url, headers=..., json=...)`` 시그니처(``requests``
    모듈과 호환)만을 요구한다.
  - 반환값은 ``{"status", "comment_id", "message"}`` 로 정규화된다.
  - 실패 메시지에는 raw 응답 본문을 포함하지 않는다 (토큰/예기치 않은
    페이로드 유출 방지).
"""

from __future__ import annotations

from typing import Any, Optional


def _default_http_client():
    import requests

    return requests


def post_or_update_pr_comment(
    *,
    token: str,
    repo: str,
    pr_number: int,
    body: str,
    marker: str = "🔍 Dallo 보안 분석 결과",
    http_client: Any = None,
) -> dict:
    """기존 Dallo 코멘트가 있으면 업데이트, 없으면 생성한다.

    동작 순서 (기존 ``post_comment()`` 동작과 일치):
      1. ``GET /repos/{repo}/issues/{pr_number}/comments``
      2. 200 응답에서 ``marker`` 가 포함된 코멘트가 있으면 해당 코멘트
         ``url`` 로 PATCH ``{"body": body}``.
      3. PATCH 가 200 이면 ``status="updated"`` 로 반환.
      4. 그 외 (코멘트 없음/마커 불일치/PATCH 실패) 는 POST 로
         새 코멘트 생성. 201 이면 ``status="created"``.
      5. POST 가 201 이 아니면 ``status="failed"`` 로 status_code 만
         포함한 안전 메시지 반환.
    """
    client = http_client if http_client is not None else _default_http_client()
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    existing = client.get(url, headers=headers)
    if getattr(existing, "status_code", None) == 200:
        for comment in existing.json():
            if marker in comment.get("body", ""):
                resp = client.patch(
                    comment["url"], headers=headers, json={"body": body}
                )
                if getattr(resp, "status_code", None) == 200:
                    cid = comment.get("id")
                    return {
                        "status": "updated",
                        "comment_id": cid,
                        "message": f"[+] 기존 PR 코멘트 업데이트 완료 (ID: {cid})",
                    }

    resp = client.post(url, headers=headers, json={"body": body})
    if getattr(resp, "status_code", None) == 201:
        return {
            "status": "created",
            "comment_id": _safe_extract_id(resp),
            "message": "[+] PR 코멘트 생성 완료",
        }

    status_code = getattr(resp, "status_code", None)
    return {
        "status": "failed",
        "comment_id": None,
        "message": f"[!] PR 코멘트 생성 실패: {status_code}",
    }


def _safe_extract_id(resp: Any) -> Optional[int]:
    try:
        data = resp.json()
    except Exception:
        return None
    if isinstance(data, dict):
        cid = data.get("id")
        if isinstance(cid, int):
            return cid
    return None


__all__ = ["post_or_update_pr_comment"]
