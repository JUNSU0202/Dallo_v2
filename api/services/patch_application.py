"""패치 적용 서비스 (api/services/patch_application.py).

Wave 2-L: ``api/routers/patch.py`` 에 들어 있던 패치 적용 비즈니스 로직을
HTTP 계층 외부로 분리한 모듈. 라우터는 요청 모델을 파싱한 뒤
``apply_patch_workflow`` 를 호출하기만 하면 된다.

Wave 3-E: GitHub HTTP 인프라 호출(refs/contents/commits/pulls)을
``api.services.github_patch_adapter`` 로 분리. 본 use-case 모듈은 다음만
담당한다:
  - unified diff 생성
  - 로컬 ``applied/`` 디렉터리 저장 (sanitize 포함)
  - base result 셰이프 조립
  - 토큰/레포 환경변수 폴백
  - 토큰/레포가 있을 때 GitHub 어댑터에 위임 + 예외 가드

설계 원칙:
  - FastAPI/Pydantic 의존 없음.
  - ``api.server`` 를 import 하지 않는다 (순환 import 방지).
  - 모듈 최상위에서 ``requests`` 를 import 하지 않는다 (어댑터가 lazy 처리).
  - GitHub 토큰은 응답/메시지/diff 어디에도 노출하지 않는다.
"""

from __future__ import annotations

import os
from typing import List

from api.services import github_patch_adapter, safe_paths


def sanitize_filename(filename: str) -> str:
    """파일명을 sanitize 한다 (Wave 3-B: ``safe_paths`` 위임).

    로컬 ``applied/`` 디렉터리에 저장할 때 디렉터리 트래버설을 막고,
    중첩 디렉터리를 만들지 않도록 한다. 응답에 노출되는 ``filename``
    필드는 호출자가 원본 그대로 보존해야 한다 (이 함수의 책임이 아님).
    """
    return safe_paths.sanitize_filename(filename)


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
    토큰/레포가 있으면 ``github_patch_adapter.create_pull_request`` 에
    위임하고, 어댑터가 반환한 부분 결과를 base result 에 병합한다.
    어댑터에서 발생한 예외는 ``"GitHub 연동 오류: ..."`` 메시지로 변환한다.
    """
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

    try:
        update = github_patch_adapter.create_pull_request(
            token=token,
            repo=repo,
            filename=filename,
            fixed_code=fixed_code,
            vulnerability_id=vulnerability_id,
            fix_type=fix_type,
            diff=diff,
        )
        result.update(update)
    except Exception as e:
        result["message"] = f"GitHub 연동 오류: {str(e)}"

    return result


__all__ = [
    "sanitize_filename",
    "build_unified_diff",
    "save_local_patch",
    "apply_patch_workflow",
]
