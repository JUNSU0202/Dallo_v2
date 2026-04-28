"""패치 적용 라우터 (api/routers/patch.py).

Wave 2-F: api/server.py 에서 분리된 POST /api/apply-patch 엔드포인트.
Wave 2-L: 비즈니스 로직(diff 생성, 로컬 저장, GitHub 워크플로)은
``api.services.patch_application`` 으로 이전. 이 모듈은 요청 모델 + 엔드포인트
+ 의존성 + 서비스 호출만 담당하는 얇은 라우터를 유지한다.

엔드포인트:
  - POST /api/apply-patch

설계 메모:
  - 업로드 디렉터리 기본값은 ``api.settings.UPLOAD_DIR`` 에서 가져오되,
    모듈 변수 ``UPLOAD_DIR`` 로 재노출하여 기존 테스트의
    ``monkeypatch.setattr(patch_router, "UPLOAD_DIR", ...)`` 패턴을 지원한다.
  - api.server 를 import 하지 않아 순환 import 위험이 없다.
  - 토큰 값은 응답 메시지/로그 어디에도 노출하지 않는다.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api.auth import verify_api_key
from api.services.patch_application import apply_patch_workflow
from api.settings import UPLOAD_DIR as _SETTINGS_UPLOAD_DIR

router = APIRouter()

# 모듈 레벨 바인딩으로 노출하여 monkeypatch 호환성을 유지한다.
UPLOAD_DIR = _SETTINGS_UPLOAD_DIR


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
    """수정안 적용: 로컬 저장 + (선택) GitHub 브랜치/커밋/PR 생성."""
    return apply_patch_workflow(
        original_code=req.original_code,
        fixed_code=req.fixed_code,
        filename=req.filename,
        vulnerability_id=req.vulnerability_id,
        fix_type=req.fix_type,
        github_repo=req.github_repo,
        github_token=req.github_token,
        upload_dir=UPLOAD_DIR,
    )
