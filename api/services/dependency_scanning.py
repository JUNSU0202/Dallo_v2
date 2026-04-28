"""의존성 스캔 서비스 (api/services/dependency_scanning.py).

Wave 2-N: ``api/routers/dependencies.py`` 에 들어 있던 의존성 스캔 비즈니스
로직을 HTTP 계층 외부로 분리한 모듈. 라우터는 요청 모델을 파싱한 뒤
``scan_dependencies_workflow`` 를 호출하기만 하면 된다.

설계 원칙:
  - FastAPI/Pydantic 의존 없음. 순수 함수 + dict 반환.
  - ``api.server`` 를 import 하지 않는다 (순환 import 방지).
  - ``DependencyScanner`` 는 워크플로 호출 시점에 lazy 하게 import 한다.
    api 패키지 import 만으로 외부 도구(pip-audit / npm) 경로가 끌려오지
    않도록 하고, 테스트가 ``analyzer.dependency_scanner`` 모듈을 monkeypatch
    하여 외부 프로세스를 차단할 수 있게 한다.

보안 가드 (project_path):
  - 인증된 사용자라 하더라도 서버 로컬의 임의 경로를 스캔할 수 있어선 안 된다.
  - 기본 허용 루트는 ``api.result_sources.project_root()`` 이며,
    ``project_path`` 가 주어지면 정규화 후 허용 루트의 하위인지 검사한다.
  - 허용 루트 바깥인 경우 외부 도구를 호출하지 않고, 동일한 응답 셰이프를
    유지하는 안전한 에러 결과 dict 한 개를 반환한다.
"""

from __future__ import annotations

import os
from typing import Optional

from api import result_sources


def _safe_error_result(message: str) -> dict:
    """스캐너 결과 dict 와 동일한 셰이프의 안전한 자리표시자."""
    return {
        "tool": "none",
        "project_path": "",
        "summary": {
            "total_packages": 0,
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "vulnerabilities": [],
        "packages": [],
        "error": message,
    }


def _is_within(child: str, parent: str) -> bool:
    """``child`` 가 ``parent`` 의 하위 경로인지 검사 (둘 다 정규화 후 비교).

    심볼릭 링크를 통한 우회를 막기 위해 ``os.path.realpath`` 로 정규화한다.
    """
    child_real = os.path.realpath(child)
    parent_real = os.path.realpath(parent)
    try:
        common = os.path.commonpath([child_real, parent_real])
    except ValueError:
        # 다른 드라이브/루트 등 commonpath 가 실패하는 경우는 외부로 간주.
        return False
    return common == parent_real


def scan_dependencies_workflow(
    *,
    requirements_text: str = "",
    package_json_text: str = "",
    project_path: str = "",
    allowed_root: Optional[str] = None,
) -> list[dict]:
    """의존성 스캔 분기 로직.

    우선순위:
      1. ``requirements_text`` 가 비어 있지 않으면 requirements 분기.
      2. 그 외 ``package_json_text`` 가 비어 있지 않으면 package.json 분기.
      3. 그 외 ``project_path`` 가 비어 있지 않고 실재하면:
         - ``allowed_root`` 의 하위인 경우에만 스캐너에 전달.
         - 외부인 경우 안전 에러 결과 1개를 반환.
      4. 그 외(모두 비어 있거나 project_path 가 실재하지 않으면)
         ``allowed_root`` 자체를 스캔.

    Returns:
        스캐너 결과 dict 의 리스트. 응답 셰이프는 라우터의 기존 동작과 동일.
    """
    from analyzer.dependency_scanner import DependencyScanner
    scanner = DependencyScanner()

    if requirements_text:
        return [scanner.scan_requirements_text(requirements_text).to_dict()]

    if package_json_text:
        return [scanner.scan_package_json_text(package_json_text).to_dict()]

    root = allowed_root if allowed_root is not None else result_sources.project_root()

    if project_path and os.path.exists(project_path):
        if _is_within(project_path, root):
            return [r.to_dict() for r in scanner.scan(os.path.realpath(project_path))]
        return [_safe_error_result(
            "project_path is not allowed (outside project root)"
        )]

    return [r.to_dict() for r in scanner.scan(root)]


__all__ = ["scan_dependencies_workflow"]
