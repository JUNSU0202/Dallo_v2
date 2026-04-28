"""분석/잡 라우터 (api/routers/analyze.py).

Wave 2-G: api/server.py 에서 분리된 분석 실행/상태 엔드포인트.
공개 URL/응답 셰이프/dependencies(verify_api_key)/상태 코드/Celery 폴백 동작은
그대로 보존된다.

엔드포인트:
  - POST /api/analyze
  - GET  /api/analyze/status/{task_id}
  - GET  /api/analyze/{job_id}
  - POST /api/analyze/file

설계 메모:
  - analyzer.pipeline / reports.report_generator / celery 임포트는 모두
    함수 내부 lazy import 로 처리하여 api 패키지 임포트 시 외부 라이브러리
    부담을 최소화한다 (테스트가 모듈 로드 시점에 LLM/Celery 의존성을 끌고
    오지 않도록 한다).
  - 메모리 잡 상태(analysis_jobs)/Celery 토글(_USE_CELERY)/_run_analysis 는
    이 모듈에 모아두고 서버는 라우터를 include 만 한다 (api.server 미의존).
  - 테스트는 api.routers.analyze 의 _run_analysis / _USE_CELERY 를
    monkeypatch 하여 백그라운드/Celery 의존성을 끊을 수 있다.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from threading import Thread

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, UploadFile
from pydantic import BaseModel

from api.auth import verify_api_key
from api.dto.responses import AnalyzeStartResponse
from api.result_sources import REPORTS_DIR

router = APIRouter()

# 분석 작업 상태 저장 (메모리 — Celery 미사용 시 fallback)
analysis_jobs: dict = {}

# Celery 사용 가능 여부 감지 — Redis 연결 실패 시 자동으로 메모리 폴백
_USE_CELERY = False
_celery = None
run_analysis_task = None
try:
    from api.celery_app import celery_app as _celery  # noqa: F401
    from api.tasks import run_analysis_task as run_analysis_task  # noqa: F401
    _celery.connection_for_write().ensure_connection(max_retries=1, timeout=2)
    _USE_CELERY = True
except Exception:
    _USE_CELERY = False


class AnalyzeRequest(BaseModel):
    code: str
    filename: str = "uploaded_code.py"
    use_llm: bool = True
    multi_patch: bool = False
    provider: str = "gemini"
    model: str = "gemini-2.0-flash-lite"


def _run_analysis(
    job_id: str,
    code: str,
    filename: str,
    use_llm: bool,
    provider: str,
    model: str,
    multi_patch: bool = False,
):
    """백그라운드에서 분석 파이프라인 실행 (analyzer.pipeline에 위임)."""
    from analyzer.pipeline import execute_pipeline

    analysis_jobs[job_id]["status"] = "analyzing"

    def on_progress(step: str):
        analysis_jobs[job_id]["step"] = step

    try:
        result = execute_pipeline(
            job_id=job_id, code=code, filename=filename,
            use_llm=use_llm, provider=provider, model=model,
            multi_patch=multi_patch, on_progress=on_progress,
        )

        analysis_jobs[job_id]["language"] = result.language
        if result.llm_error:
            analysis_jobs[job_id]["llm_error"] = result.llm_error
        if result.db_error:
            analysis_jobs[job_id]["db_error"] = result.db_error

        result_data = result.result_data

        # JSON 파일로 저장 (server 전용 — Celery task에서는 생략)
        os.makedirs(REPORTS_DIR, exist_ok=True)
        with open(os.path.join(REPORTS_DIR, "full_result.json"), "w", encoding="utf-8") as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)

        # 리포트 자동 생성 (server 전용)
        analysis_jobs[job_id]["step"] = "리포트 생성 중..."
        try:
            from reports.report_generator import ReportGenerator
            report_gen = ReportGenerator()
            report_files = report_gen.save_report(result_data, output_dir=REPORTS_DIR, fmt="both")
            analysis_jobs[job_id]["report_files"] = {
                k: f"/api/report/download/{os.path.basename(v)}"
                for k, v in report_files.items()
            }
        except Exception as e:
            analysis_jobs[job_id]["report_error"] = str(e)

        analysis_jobs[job_id]["status"] = "completed"
        analysis_jobs[job_id]["result"] = result_data
        analysis_jobs[job_id]["step"] = "완료"

    except Exception as e:
        analysis_jobs[job_id]["status"] = "failed"
        analysis_jobs[job_id]["error"] = str(e)
        analysis_jobs[job_id]["step"] = f"오류: {str(e)}"


@router.post(
    "/api/analyze",
    response_model=AnalyzeStartResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def start_analysis(req: AnalyzeRequest, background_tasks: BackgroundTasks):
    """코드를 제출하여 분석을 시작합니다. Celery 사용 가능 시 task로 제출."""
    if _USE_CELERY:
        # Celery task로 제출
        task = run_analysis_task.delay(
            code=req.code, filename=req.filename,
            use_llm=req.use_llm, provider=req.provider,
            model=req.model, multi_patch=req.multi_patch,
        )
        return {
            "job_id": task.id,
            "status": "queued",
            "message": "분석이 시작되었습니다. (Celery)",
            "backend": "celery",
        }

    # Celery 미사용 fallback — 기존 메모리 방식
    job_id = f"job_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"

    analysis_jobs[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "step": "대기 중...",
        "filename": req.filename,
        "code_length": len(req.code),
        "use_llm": req.use_llm,
        "created_at": datetime.now().isoformat(),
        "result": None,
        "error": None,
    }

    background_tasks.add_task(
        _run_analysis, job_id, req.code, req.filename,
        req.use_llm, req.provider, req.model, req.multi_patch,
    )

    return {
        "job_id": job_id,
        "status": "queued",
        "message": "분석이 시작되었습니다.",
        "backend": "memory",
    }


@router.get("/api/analyze/status/{task_id}", dependencies=[Depends(verify_api_key)])
def get_celery_task_status(task_id: str):
    """Celery task 상태를 조회합니다. (AsyncResult 기반)"""
    if not _USE_CELERY:
        return {"error": "Celery가 활성화되어 있지 않습니다."}

    from celery.result import AsyncResult
    result = AsyncResult(task_id, app=_celery)

    response = {
        "task_id": task_id,
        "status": result.state,  # PENDING / STARTED / PROGRESS / SUCCESS / FAILURE
    }

    if result.state == "PROGRESS":
        response.update(result.info or {})
    elif result.state == "SUCCESS":
        response["result"] = result.result
    elif result.state == "FAILURE":
        response["error"] = str(result.result)

    return response


@router.get("/api/analyze/{job_id}", dependencies=[Depends(verify_api_key)])
def get_analysis_status(job_id: str):
    """분석 작업 상태를 조회합니다. (메모리 방식 + Celery 자동 감지)"""
    # 메모리에서 먼저 조회
    job = analysis_jobs.get(job_id)
    if job:
        return job

    # Celery에서 조회 시도
    if _USE_CELERY:
        from celery.result import AsyncResult
        result = AsyncResult(job_id, app=_celery)
        if result.state != "PENDING":
            response = {
                "job_id": job_id,
                "status": result.state.lower(),
                "step": "완료" if result.state == "SUCCESS" else result.state,
            }
            if result.state == "PROGRESS":
                response.update(result.info or {})
            elif result.state == "SUCCESS":
                response["result"] = result.result.get("result") if isinstance(result.result, dict) else None
                response["status"] = result.result.get("status", "completed") if isinstance(result.result, dict) else "completed"
            elif result.state == "FAILURE":
                response["error"] = str(result.result)
                response["status"] = "failed"
            return response

    return {"error": "Job not found"}


@router.post("/api/analyze/file", dependencies=[Depends(verify_api_key)])
async def analyze_file(file: UploadFile = File(...), use_llm: bool = Form(True)):
    """파일을 업로드하여 분석합니다."""
    content = await file.read()
    code = content.decode("utf-8")

    req = AnalyzeRequest(code=code, filename=file.filename or "uploaded.py", use_llm=use_llm)

    # 동기 실행 (파일 업로드는 즉시 결과 반환)
    job_id = f"job_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    analysis_jobs[job_id] = {
        "job_id": job_id, "status": "queued", "step": "시작",
        "filename": req.filename, "created_at": datetime.now().isoformat(),
        "result": None, "error": None,
    }

    t = Thread(
        target=_run_analysis,
        args=(job_id, req.code, req.filename, req.use_llm, req.provider, req.model),
    )
    t.start()

    return {"job_id": job_id, "status": "queued"}
