"""패치 적용 서비스 (api/services/patch_application.py).

Wave 2-L: ``api/routers/patch.py`` 에 들어 있던 패치 적용 비즈니스 로직을
HTTP 계층 외부로 분리한 모듈. 라우터는 요청 모델을 파싱한 뒤
``apply_patch_workflow`` 를 호출하기만 하면 된다.

설계 원칙:
  - FastAPI/Pydantic 의존 없음. 순수 함수 + 표준 라이브러리 + (lazy) requests.
  - ``api.server`` 를 import 하지 않는다 (순환 import 방지).
  - ``requests`` 는 워크플로 내부에서 import 하여 모듈 임포트 비용을 낮추고,
    테스트가 ``sys.modules['requests']`` 패치로 네트워크를 차단할 수 있도록 한다.
  - GitHub 토큰은 응답/메시지/diff 어디에도 노출하지 않는다.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import List


def sanitize_filename(filename: str) -> str:
    """파일명에 포함된 ``/`` 와 ``\\`` 를 ``_`` 로 평탄화한다.

    로컬 ``applied/`` 디렉터리에 저장할 때 디렉터리 트래버설을 막고,
    중첩 디렉터리를 만들지 않도록 한다. 응답에 노출되는 ``filename``
    필드는 호출자가 원본 그대로 보존해야 한다 (이 함수의 책임이 아님).
    """
    return filename.replace("/", "_").replace("\\", "_")


def build_unified_diff(
    original_code: str, fixed_code: str, filename: str,
) -> List[str]:
    """원본/수정 코드의 unified diff 라인 리스트를 반환한다."""
    import difflib

    original_lines = original_code.splitlines(keepends=True)
    fixed_lines = fixed_code.splitlines(keepends=True)
    return list(difflib.unified_diff(
        original_lines, fixed_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        lineterm="",
    ))


def save_local_patch(upload_dir: str, filename: str, fixed_code: str) -> str:
    """``upload_dir/applied/<safe_filename>`` 에 수정 코드를 기록하고 경로를 반환."""
    safe_filename = sanitize_filename(filename)
    applied_dir = os.path.join(upload_dir, "applied")
    os.makedirs(applied_dir, exist_ok=True)
    target = os.path.join(applied_dir, safe_filename)
    with open(target, "w", encoding="utf-8") as f:
        f.write(fixed_code)
    return target


def apply_patch_workflow(
    *,
    original_code: str,
    fixed_code: str,
    filename: str,
    vulnerability_id: str,
    fix_type: str = "recommended",
    github_repo: str = "",
    github_token: str = "",
    upload_dir: str,
) -> dict:
    """패치 적용 워크플로 — 로컬 저장 + (선택) GitHub 브랜치/커밋/PR 생성.

    토큰/레포가 없으면 로컬 저장 후 ``applied_local`` 상태로 즉시 반환한다.
    GitHub 호출은 ``sys.modules['requests']`` 를 통해 lazy 하게 이루어진다.
    """
    import base64
    import requests as http_requests

    diff = build_unified_diff(original_code, fixed_code, filename)
    original_lines_count = len(original_code.splitlines(keepends=True))
    fixed_lines_count = len(fixed_code.splitlines(keepends=True))

    save_local_patch(upload_dir, filename, fixed_code)

    result: dict = {
        "status": "applied_local",
        "filename": filename,
        "vulnerability_id": vulnerability_id,
        "fix_type": fix_type,
        "diff": "\n".join(diff),
        "original_lines": original_lines_count,
        "fixed_lines": fixed_lines_count,
        "pr_url": None,
        "branch": None,
    }

    token = github_token or os.environ.get("GITHUB_TOKEN", "")
    repo = github_repo or os.environ.get("GITHUB_REPOSITORY", "")

    if not token or not repo:
        result["message"] = "로컬 저장 완료 (GITHUB_TOKEN 미설정 — PR 생성 스킵)"
        return result

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    api_base = f"https://api.github.com/repos/{repo}"

    try:
        # 1. main 브랜치 최신 SHA
        ref_resp = http_requests.get(
            f"{api_base}/git/ref/heads/main", headers=headers, timeout=10,
        )
        if ref_resp.status_code != 200:
            result["message"] = f"main 브랜치 조회 실패: {ref_resp.status_code}"
            return result
        main_sha = ref_resp.json()["object"]["sha"]

        # 2. 새 브랜치 생성
        branch_name = (
            f"fix/{vulnerability_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        create_ref = http_requests.post(
            f"{api_base}/git/refs",
            headers=headers,
            json={"ref": f"refs/heads/{branch_name}", "sha": main_sha},
            timeout=10,
        )
        if create_ref.status_code not in (200, 201):
            result["message"] = f"브랜치 생성 실패: {create_ref.status_code}"
            return result

        # 3. 기존 파일 SHA 조회 (있으면 PUT 시 필요)
        file_resp = http_requests.get(
            f"{api_base}/contents/{filename}?ref={branch_name}",
            headers=headers, timeout=10,
        )
        file_sha = (
            file_resp.json().get("sha") if file_resp.status_code == 200 else None
        )

        # 4. 커밋
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

        commit_resp = http_requests.put(
            f"{api_base}/contents/{filename}",
            headers=headers,
            json=commit_data,
            timeout=10,
        )
        if commit_resp.status_code not in (200, 201):
            result["message"] = (
                f"커밋 실패: {commit_resp.status_code} {commit_resp.text[:200]}"
            )
            return result

        # 5. Pull Request 생성
        pr_body = f"""## 🤖 Dallo AI 보안 수정안

**취약점**: `{vulnerability_id}`
**수정 유형**: {fix_type}
**파일**: `{filename}`

### Diff
```diff
{chr(10).join(diff)}
```

---
*🛡️ Dallo DevSecOps — AI 자동 수정안*
"""
        pr_resp = http_requests.post(
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
            result["status"] = "pr_created"
            result["pr_url"] = pr_data["html_url"]
            result["pr_number"] = pr_data["number"]
            result["branch"] = branch_name
            result["message"] = f"PR #{pr_data['number']} 생성 완료"
        else:
            result["status"] = "committed"
            result["branch"] = branch_name
            result["message"] = (
                f"브랜치 커밋 완료, PR 생성 실패: {pr_resp.status_code}"
            )

    except Exception as e:
        result["message"] = f"GitHub 연동 오류: {str(e)}"

    return result


__all__ = [
    "sanitize_filename",
    "build_unified_diff",
    "save_local_patch",
    "apply_patch_workflow",
]
