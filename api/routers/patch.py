"""패치 적용 라우터 (api/routers/patch.py).

Wave 2-F: api/server.py 에서 분리된 POST /api/apply-patch 엔드포인트.
공개 URL/응답 JSON 셰이프/dependencies(verify_api_key)/상태 코드는 그대로
보존된다. 토큰/레포가 누락된 경우 로컬 저장 폴백 동작도 그대로 유지한다.

엔드포인트:
  - POST /api/apply-patch

설계 메모:
  - requests / base64 / difflib 임포트는 함수 내부에서 lazy 로 처리하여
    api 패키지 임포트 시 외부 네트워크 라이브러리 import 비용을 줄인다.
  - 업로드 디렉터리는 모듈 변수 UPLOAD_DIR 로 노출하여 테스트가 monkeypatch
    할 수 있게 한다 (server.py 와 동일한 기본값).
  - api.server 를 import 하지 않아 순환 import 위험이 없다.
  - 토큰 값은 응답 메시지/로그 어디에도 노출하지 않는다.
"""

from __future__ import annotations

import os
from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api.auth import verify_api_key

router = APIRouter()

UPLOAD_DIR = "uploads"


class ApplyPatchRequest(BaseModel):
    original_code: str
    fixed_code: str
    filename: str
    vulnerability_id: str
    fix_type: str = "recommended"
    github_repo: str = ""     # 사용자의 GitHub 레포 (owner/repo)
    github_token: str = ""    # 사용자의 GitHub 토큰


@router.post("/api/apply-patch", dependencies=[Depends(verify_api_key)])
def apply_patch(req: ApplyPatchRequest):
    """
    수정안을 적용합니다.
    1. 수정 코드로 새 브랜치 생성
    2. 해당 브랜치에 커밋
    3. Pull Request 자동 생성
    4. Diff도 함께 반환
    """
    import difflib
    import base64
    import requests as http_requests

    # diff 생성
    original_lines = req.original_code.splitlines(keepends=True)
    fixed_lines = req.fixed_code.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        original_lines, fixed_lines,
        fromfile=f"a/{req.filename}",
        tofile=f"b/{req.filename}",
        lineterm="",
    ))

    # 로컬에도 저장
    safe_filename = req.filename.replace("/", "_").replace("\\", "_")
    applied_dir = os.path.join(UPLOAD_DIR, "applied")
    os.makedirs(applied_dir, exist_ok=True)
    with open(os.path.join(applied_dir, safe_filename), "w", encoding="utf-8") as f:
        f.write(req.fixed_code)

    result = {
        "status": "applied_local",
        "filename": req.filename,
        "vulnerability_id": req.vulnerability_id,
        "fix_type": req.fix_type,
        "diff": "\n".join(diff),
        "original_lines": len(original_lines),
        "fixed_lines": len(fixed_lines),
        "pr_url": None,
        "branch": None,
    }

    # GitHub 브랜치 + PR 생성 시도
    # 사용자가 입력한 레포/토큰 우선, 없으면 서버 환경변수 폴백
    token = req.github_token or os.environ.get("GITHUB_TOKEN", "")
    repo = req.github_repo or os.environ.get("GITHUB_REPOSITORY", "")

    if not token or not repo:
        result["message"] = "로컬 저장 완료 (GITHUB_TOKEN 미설정 — PR 생성 스킵)"
        return result

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    api_base = f"https://api.github.com/repos/{repo}"

    try:
        # 1. main 브랜치의 최신 SHA 가져오기
        ref_resp = http_requests.get(f"{api_base}/git/ref/heads/main", headers=headers, timeout=10)
        if ref_resp.status_code != 200:
            result["message"] = f"main 브랜치 조회 실패: {ref_resp.status_code}"
            return result
        main_sha = ref_resp.json()["object"]["sha"]

        # 2. 새 브랜치 생성 (fix/vuln_id_timestamp)
        branch_name = f"fix/{req.vulnerability_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        create_ref = http_requests.post(
            f"{api_base}/git/refs",
            headers=headers,
            json={"ref": f"refs/heads/{branch_name}", "sha": main_sha},
            timeout=10,
        )
        if create_ref.status_code not in (200, 201):
            result["message"] = f"브랜치 생성 실패: {create_ref.status_code}"
            return result

        # 3. 파일이 기존에 있는지 확인 (있으면 SHA 필요)
        file_path = req.filename
        file_resp = http_requests.get(
            f"{api_base}/contents/{file_path}?ref={branch_name}",
            headers=headers, timeout=10,
        )
        file_sha = file_resp.json().get("sha") if file_resp.status_code == 200 else None

        # 4. 수정된 코드를 브랜치에 커밋
        content_b64 = base64.b64encode(req.fixed_code.encode("utf-8")).decode("utf-8")
        commit_data = {
            "message": f"fix: {req.vulnerability_id} 보안 취약점 수정 ({req.fix_type})\n\nDallo AI 자동 수정안 적용",
            "content": content_b64,
            "branch": branch_name,
        }
        if file_sha:
            commit_data["sha"] = file_sha

        commit_resp = http_requests.put(
            f"{api_base}/contents/{file_path}",
            headers=headers,
            json=commit_data,
            timeout=10,
        )
        if commit_resp.status_code not in (200, 201):
            result["message"] = f"커밋 실패: {commit_resp.status_code} {commit_resp.text[:200]}"
            return result

        # 5. Pull Request 생성
        pr_body = f"""## 🤖 Dallo AI 보안 수정안

**취약점**: `{req.vulnerability_id}`
**수정 유형**: {req.fix_type}
**파일**: `{req.filename}`

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
                "title": f"🤖 fix: {req.vulnerability_id} 보안 취약점 수정",
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
            result["message"] = f"브랜치 커밋 완료, PR 생성 실패: {pr_resp.status_code}"

    except Exception as e:
        result["message"] = f"GitHub 연동 오류: {str(e)}"

    return result
