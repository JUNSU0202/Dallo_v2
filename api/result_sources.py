"""분석 결과 파일 로더 (api/result_sources.py).

Wave 2-B 라우터 분리 과정에서 추출된 순수 헬퍼 모듈입니다.
api.server 와 api.routers.* 양쪽에서 동일한 데이터 소스를 공유하기 위한
의존성 없는 어댑터 계층입니다 (FastAPI/DB 의존 X).

Wave 2-O 하드닝
---------------
- ``REPORTS_DIR`` 기본값을 cwd 가 아닌 repo root 기준 absolute path 로 설정.
- 깨진 JSON / dict 가 아닌 valid JSON 모두에 대해 안전한 fallback 반환
  (대시보드/리포트 엔드포인트가 손상된 파일에 의해 500 으로 떨어지지 않도록).
- 테스트가 ``result_sources.REPORTS_DIR = tmp_dir`` 로 monkeypatch 하는
  기존 패턴은 그대로 유지된다.
"""

import json
import os


def project_root() -> str:
    """레포지토리 루트 경로 (api/ 의 부모).

    의존성 스캐너가 현재 프로젝트를 스캔할 때 사용한다. 라우터들은
    파일 위치(api/routers/*.py)에 따라 상대 경로 계산이 달라지므로,
    한 곳에서 공유 헬퍼로 노출하여 일관성을 보장한다.
    """
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# repo root 기준 absolute path. cwd 변동에 영향받지 않는다.
# 테스트에서는 ``monkeypatch.setattr(result_sources, "REPORTS_DIR", str(tmp))``
# 로 격리할 수 있다.
REPORTS_DIR = os.path.join(project_root(), "reports")


def reports_path(filename: str) -> str:
    """현재 ``REPORTS_DIR`` 기준 파일 경로를 돌려준다.

    monkeypatch 시점에 동적으로 ``REPORTS_DIR`` 을 다시 읽어야 하므로
    모듈 글로벌을 매 호출마다 참조한다.
    """
    return os.path.join(REPORTS_DIR, filename)


def _load_json_dict(filename: str, fallback: dict) -> dict:
    """JSON 파일을 dict 로 로드. 부재/파싱 실패/비-dict 모두 fallback."""
    path = reports_path(filename)
    if not os.path.exists(path):
        return fallback
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return fallback
    if not isinstance(data, dict):
        return fallback
    return data


def load_bandit_report() -> dict:
    """Bandit 리포트 로드 (없거나 손상되면 빈 셰이프 반환)."""
    return _load_json_dict(
        "bandit_report.json",
        {"results": [], "metrics": {"_totals": {}}},
    )


def load_full_result() -> dict:
    """전체 파이프라인 결과 로드 (없거나 손상되면 빈 dict)."""
    return _load_json_dict("full_result.json", {})
