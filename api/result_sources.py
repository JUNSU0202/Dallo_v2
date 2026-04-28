"""분석 결과 파일 로더 (api/result_sources.py).

Wave 2-B 라우터 분리 과정에서 추출된 순수 헬퍼 모듈입니다.
api.server 와 api.routers.* 양쪽에서 동일한 데이터 소스를 공유하기 위한
의존성 없는 어댑터 계층입니다 (FastAPI/DB 의존 X).
"""

import json
import os

REPORTS_DIR = "reports"


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
