"""의존성 스캔 라우터 (api/routers/dependencies.py).

Wave 2-E: api/server.py 에서 분리된 의존성(SBOM/CVE) 스캔 엔드포인트.
Wave 2-N: 비즈니스 로직(분기 선택, 스캐너 호출, project_path 보안 가드)은
``api.services.dependency_scanning`` 으로 이전. 이 모듈은 요청 모델 +
엔드포인트 + 인증 의존성 + 서비스 호출만 담당하는 얇은 라우터를 유지한다.

엔드포인트:
  - GET  /api/dependencies
  - POST /api/dependencies/scan

설계 메모:
  - 공개 URL/응답 셰이프/dependencies(verify_api_key)/상태 코드는 그대로 보존.
  - api.server 를 import 하지 않아 순환 import 위험이 없다.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api.auth import verify_api_key
from api.services.dependency_scanning import scan_dependencies_workflow

router = APIRouter()


class DependencyScanRequest(BaseModel):
    requirements_text: str = ""      # requirements.txt 내용
    package_json_text: str = ""      # package.json 내용
    project_path: str = ""           # 프로젝트 경로 (서버 로컬, project_root 내부만 허용)


@router.post("/api/dependencies/scan", dependencies=[Depends(verify_api_key)])
def scan_dependencies(req: DependencyScanRequest):
    """의존성 취약점을 스캔합니다."""
    results = scan_dependencies_workflow(
        requirements_text=req.requirements_text,
        package_json_text=req.package_json_text,
        project_path=req.project_path,
    )
    return {"results": results}


@router.get("/api/dependencies", dependencies=[Depends(verify_api_key)])
def get_dependencies():
    """현재 프로젝트의 의존성 스캔 결과를 반환합니다."""
    results = scan_dependencies_workflow()
    return {"results": results}
