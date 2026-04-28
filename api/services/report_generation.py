"""리포트 생성 서비스 (api/services/report_generation.py).

Wave 2-R: ``api/routers/report.py`` 에 들어 있던 데이터 로드 / 의존성 스캔
헬퍼 로직을 HTTP 계층 외부로 분리한 모듈. 라우터는 요청 파라미터를
파싱한 뒤 ``load_report_data`` 와 ``scan_dependencies_safely`` 를 호출하기만
하면 된다.

설계 원칙:
  - FastAPI 의존 없음. 순수 함수 + dict / Optional 반환.
  - ``api.server`` 를 import 하지 않는다 (순환 import 방지).
  - ``DependencyScanner`` 는 호출 시점에 lazy 하게 import 한다. api 패키지
    import 만으로 외부 도구(pip-audit / npm) 경로가 끌려오지 않게 하고,
    테스트가 ``analyzer.dependency_scanner`` 모듈을 monkeypatch 하여 외부
    프로세스를 차단할 수 있게 한다.
  - DB → JSON 폴백 우선순위는 라우터 inline 로직과 동일하게 유지한다
    (DB 데이터가 비면 ``result_sources.load_full_result`` 로 폴백, 그 결과가
    빈 dict 면 ``None``).
"""

from __future__ import annotations

from typing import Optional

from api import result_sources
from db import service as db_service


def load_report_data(session_id: Optional[str]) -> Optional[dict]:
    """DB → JSON 폴백 순서로 분석 결과를 로드한다.

    - ``session_id`` 가 주어지면 ``db_service.get_analysis_by_session`` 사용.
    - 그 외에는 ``db_service.get_latest_analysis`` 사용.
    - DB 가 비어 있으면 ``result_sources.load_full_result`` 로 폴백.
    - 폴백 결과가 빈 dict 면 ``None`` 을 반환한다.
    """
    if session_id:
        data = db_service.get_analysis_by_session(session_id)
    else:
        data = db_service.get_latest_analysis()
    if data:
        return data
    full = result_sources.load_full_result()
    return full or None


def scan_dependencies_safely() -> Optional[dict]:
    """의존성 스캔 결과(있으면).

    실패는 ``None`` 으로 흡수해 리포트 생성/미리보기 자체를 막지 않는다.
    스캐너는 ``result_sources.project_root()`` 를 대상으로 동작한다.
    """
    try:
        from analyzer.dependency_scanner import DependencyScanner

        scanner = DependencyScanner()
        return {"results": [r.to_dict() for r in scanner.scan(result_sources.project_root())]}
    except Exception:
        return None


__all__ = ["load_report_data", "scan_dependencies_safely"]
