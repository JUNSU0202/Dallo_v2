"""분석 결과 파일 로더 (api/result_sources.py).

Wave 2-B 라우터 분리 과정에서 추출된 순수 헬퍼 모듈입니다.
api.server 와 api.routers.* 양쪽에서 동일한 데이터 소스를 공유하기 위한
의존성 없는 어댑터 계층입니다 (FastAPI/DB 의존 X).
"""

import json
import os

REPORTS_DIR = "reports"


def project_root() -> str:
    """레포지토리 루트 경로 (api/ 의 부모).

    의존성 스캐너가 현재 프로젝트를 스캔할 때 사용한다. 라우터들은
    파일 위치(api/routers/*.py)에 따라 상대 경로 계산이 달라지므로,
    한 곳에서 공유 헬퍼로 노출하여 일관성을 보장한다.
    """
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_bandit_report() -> dict:
    """Bandit 리포트 로드 (없으면 빈 셰이프 반환)."""
    path = os.path.join(REPORTS_DIR, "bandit_report.json")
    if not os.path.exists(path):
        return {"results": [], "metrics": {"_totals": {}}}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_full_result() -> dict:
    """전체 파이프라인 결과 로드 (LLM 패치 포함, 없으면 빈 dict)."""
    path = os.path.join(REPORTS_DIR, "full_result.json")
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
