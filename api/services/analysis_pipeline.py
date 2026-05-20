"""분석 파이프라인/잡 오케스트레이션 서비스 (api/services/analysis_pipeline.py).

Wave 2-S: ``api/routers/analyze.py`` 에 들어 있던 ``_run_analysis`` 본체와
잡 메타 빌딩/잡 ID 생성 로직을 HTTP 계층 외부로 분리한 모듈. 라우터는
요청 파싱과 응답 셰이프 조립만 담당하고, 실제 파이프라인 실행 + JSON
저장 + 리포트 생성 + 잡 상태 갱신은 본 서비스가 책임진다.

설계 원칙:
  - FastAPI / api.server import 금지 (순환 import 방지 + 순수 함수 표면).
  - ``analyzer.pipeline`` / ``reports.report_generator`` 는 함수 본체 안에서
    lazy import 한다. 모듈 import 만으로 LLM/리포트 의존이 끌려오지 않게
    하고, 테스트가 각 모듈을 monkeypatch 하여 외부 호출을 차단할 수 있도록
    한다.
  - ``REPORTS_DIR`` 은 ``api.result_sources.REPORTS_DIR`` 를 호출 시점에 다시
    읽는다 (이름 박제 금지). 테스트의 ``monkeypatch.setattr(result_sources,
    'REPORTS_DIR', tmp)`` 가 그대로 반영된다 — Wave 2-P 계약 유지.
  - 잡 상태 dict 는 호출자(라우터/태스크) 가 소유하고 본 서비스에 인자로
    전달한다 (전역 상태 의존 제거). 라우터는 자신의 ``analysis_jobs`` 를
    그대로 넘긴다.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from typing import MutableMapping, Optional

from api import result_sources
from api.services import safe_paths


def make_job_id(*, now: Optional[datetime] = None) -> str:
    """``job_<YYYYmmdd_HHMMSS>_<6자hex>`` 형식의 잡 ID 를 생성한다.

    라우터의 기존 인라인 표현식과 동일한 셰이프를 보존한다 — 외부 클라이언트가
    job_id prefix 로 분기하는 회귀를 차단한다. ``now`` 미주입 시 모듈 ``datetime.now()``
    를 호출하므로 운영 동작은 그대로다 (Wave 4-T fakeable clock seam).
    """
    if now is None:
        now = datetime.now()
    return f"job_{now.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"


def build_initial_job_meta(
    *, job_id: str, filename: str, code_length: int, use_llm: bool,
    now: Optional[datetime] = None,
) -> dict:
    """POST /api/analyze 메모리 폴백용 잡 메타.

    라우터가 만들던 dict 와 동일한 키 집합/기본값을 보존한다. ``now`` 미주입 시
    ``datetime.now()`` 를 호출한다 (Wave 4-T fakeable clock seam).
    """
    if now is None:
        now = datetime.now()
    return {
        "job_id": job_id,
        "status": "queued",
        "step": "대기 중...",
        "filename": filename,
        "code_length": code_length,
        "use_llm": use_llm,
        "created_at": now.isoformat(),
        "result": None,
        "error": None,
    }


def build_upload_job_meta(
    *, job_id: str, filename: str, now: Optional[datetime] = None,
) -> dict:
    """POST /api/analyze/file 업로드용 잡 메타 (셰이프 단순)."""
    if now is None:
        now = datetime.now()
    return {
        "job_id": job_id,
        "status": "queued",
        "step": "시작",
        "filename": filename,
        "created_at": now.isoformat(),
        "result": None,
        "error": None,
    }


def execute_analysis_job(
    *,
    jobs: MutableMapping[str, dict],
    job_id: str,
    code: str,
    filename: str,
    use_llm: bool,
    provider: str,
    model: str,
    multi_patch: bool = False,
    llm_optimization=None,
    user_prompt: Optional[str] = None,
) -> None:
    """분석 파이프라인을 실행하고 ``jobs[job_id]`` 상태를 갱신한다.

    동작 요약 (라우터의 기존 ``_run_analysis`` 와 동일):
      1. ``analyzer.pipeline.execute_pipeline`` 호출 — on_progress 콜백으로
         진행 단계를 잡 메타에 기록.
      2. ``REPORTS_DIR/full_result.json`` 에 결과 dict 저장.
      3. ``reports.report_generator.ReportGenerator`` 로 HTML/MD 리포트 생성,
         실패 시 ``report_error`` 키로 흡수 (분석 자체는 completed).
      4. 파이프라인 자체 예외는 ``status=failed`` + ``error`` / ``step`` 갱신.

    ``REPORTS_DIR`` 은 호출 시점에 ``result_sources.REPORTS_DIR`` 을 다시
    읽는다 — 모듈 import 시점에 박제하지 않는다.
    """
    from analyzer.pipeline import execute_pipeline

    jobs[job_id]["status"] = "analyzing"

    def on_progress(step: str):
        jobs[job_id]["step"] = step

    try:
        # Wave 5-M: ``user_prompt`` 가 None 이면 kwarg 자체를 생략한다 —
        # pre-Wave-5-M 시그니처를 가진 fake ``execute_pipeline`` 더블과의
        # 호환을 유지하기 위한 조건부 forwarding. 값이 제공된 경우에만
        # 명시 kwarg 로 전달돼 그대로 파이프라인까지 흐른다.
        pipeline_kwargs: dict = {
            "job_id": job_id,
            "code": code,
            "filename": filename,
            "use_llm": use_llm,
            "provider": provider,
            "model": model,
            "multi_patch": multi_patch,
            "on_progress": on_progress,
            "llm_optimization": llm_optimization,
        }
        if user_prompt is not None:
            pipeline_kwargs["user_prompt"] = user_prompt
        result = execute_pipeline(**pipeline_kwargs)

        jobs[job_id]["language"] = result.language
        if result.llm_error:
            jobs[job_id]["llm_error"] = result.llm_error
        if result.db_error:
            jobs[job_id]["db_error"] = result.db_error

        result_data = result.result_data

        # 호출 시점에 REPORTS_DIR 을 다시 읽는다 — 이름 박제 금지 (Wave 2-P).
        reports_dir = result_sources.REPORTS_DIR
        os.makedirs(reports_dir, exist_ok=True)
        with open(
            os.path.join(reports_dir, "full_result.json"),
            "w", encoding="utf-8",
        ) as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)

        jobs[job_id]["step"] = "리포트 생성 중..."
        try:
            from reports.report_generator import ReportGenerator
            report_gen = ReportGenerator()
            report_files = report_gen.save_report(
                result_data, output_dir=reports_dir, fmt="both",
            )
            jobs[job_id]["report_files"] = {
                k: f"/api/report/download/{safe_paths.report_download_basename(v)}"
                for k, v in report_files.items()
            }
        except Exception as e:
            jobs[job_id]["report_error"] = str(e)

        jobs[job_id]["status"] = "completed"
        jobs[job_id]["result"] = result_data
        jobs[job_id]["step"] = "완료"

    except Exception as e:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(e)
        jobs[job_id]["step"] = f"오류: {str(e)}"


__all__ = [
    "make_job_id",
    "build_initial_job_meta",
    "build_upload_job_meta",
    "execute_analysis_job",
]
