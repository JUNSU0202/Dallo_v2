"""Red/Blue 요약 라우터 (api/routers/red_blue.py).

Wave 5-C: ``shared.red_blue.build_red_blue_summary`` 헬퍼를
``GET /api/red-blue/summary`` 인증 엔드포인트로 노출한다.

라우터는 얇은 위임만 담당한다. 데이터 로딩 / 정규화 / 빌더 호출은
``api.services.red_blue_summary.get_red_blue_summary`` 가 수행한다.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from api.auth import verify_api_key
from api.dto.responses import RedBlueSummaryResponse
from api.services import red_blue_summary as _service

router = APIRouter()


@router.get(
    "/api/red-blue/summary",
    response_model=RedBlueSummaryResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def get_red_blue_summary_endpoint():
    """Red/Blue 종합 요약 — DB 우선, JSON 폴백, 빈 셰이프 fail-closed."""
    return _service.get_red_blue_summary(include_attack_paths=True)
