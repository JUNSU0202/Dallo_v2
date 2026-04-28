"""의존성 스캔 라우터 (api/routers/dependencies.py).

Wave 2-E: api/server.py 에서 분리된 의존성(SBOM/CVE) 스캔 엔드포인트.
공개 URL/응답 셰이프/dependencies(verify_api_key)/상태 코드는 그대로 보존된다.

엔드포인트:
  - GET  /api/dependencies
  - POST /api/dependencies/scan

설계 메모:
  - DependencyScanner 임포트는 lazy 로 처리하여 api 패키지 임포트 시 외부
    툴(pip-audit / npm) 호출 경로가 끌려오지 않도록 한다.
  - 프로젝트 루트는 api.result_sources.project_root 공유 헬퍼를 사용한다
    (api/routers/report.py 와 동일 경로 보장).
  - api.server 를 import 하지 않아 순환 import 위험이 없다.
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api import result_sources
from api.auth import verify_api_key

router = APIRouter()


class DependencyScanRequest(BaseModel):
    requirements_text: str = ""      # requirements.txt 내용
    package_json_text: str = ""      # package.json 내용
    project_path: str = ""           # 프로젝트 경로 (서버 로컬)


@router.post("/api/dependencies/scan", dependencies=[Depends(verify_api_key)])
def scan_dependencies(req: DependencyScanRequest):
    """의존성 취약점을 스캔합니다."""
    from analyzer.dependency_scanner import DependencyScanner
    scanner = DependencyScanner()

    results = []
    if req.requirements_text:
        results.append(scanner.scan_requirements_text(req.requirements_text).to_dict())
    elif req.package_json_text:
        results.append(scanner.scan_package_json_text(req.package_json_text).to_dict())
    elif req.project_path and os.path.exists(req.project_path):
        results = [r.to_dict() for r in scanner.scan(req.project_path)]
    else:
        # 현재 프로젝트 스캔
        results = [r.to_dict() for r in scanner.scan(result_sources.project_root())]

    return {"results": results}


@router.get("/api/dependencies", dependencies=[Depends(verify_api_key)])
def get_dependencies():
    """현재 프로젝트의 의존성 스캔 결과를 반환합니다."""
    from analyzer.dependency_scanner import DependencyScanner
    scanner = DependencyScanner()
    results = [r.to_dict() for r in scanner.scan(result_sources.project_root())]
    return {"results": results}
