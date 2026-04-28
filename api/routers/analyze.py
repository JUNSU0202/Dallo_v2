"""분석/잡 라우터 (api/routers/analyze.py).

Wave 2-G: api/server.py 에서 분리된 분석 실행/상태 엔드포인트.
공개 URL/응답 셰이프/dependencies(verify_api_key)/상태 코드/Celery 폴백 동작은
그대로 보존된다.

엔드포인트:
  - POST /api/analyze
  - GET  /api/analyze/status/{task_id}
  - GET  /api/analyze/{job_id}
  - POST /api/analyze/file

Wave 2-S 분리 — 라우터를 얇게 (analysis pipeline service 추출):
  - 분석 파이프라인 실행 본체 / 잡 메타 빌딩 / 잡 ID 생성은
    ``api.services.analysis_pipeline`` 으로 이동했다. 라우터는 요청 파싱과
    응답 셰이프 조립, 그리고 백그라운드 디스패치(BackgroundTasks/Thread/
    Celery) 만 담당한다.
  - ``_run_analysis`` 는 서비스 ``execute_analysis_job`` 으로 위임하는
    얇은 래퍼로 남겨둔다. 테스트가 라우터 모듈에 monkeypatch 하던 기존
    표면 (``_run_analysis``, ``analysis_jobs``, ``_USE_CELERY``,
    ``_celery``, ``run_analysis_task``, ``_ensure_celery_initialized``,
    ``Thread``, ``AnalyzeRequest``) 은 그대로 보존된다.

설계 메모:
  - analyzer.pipeline / reports.report_generator / celery 임포트는 모두
    함수 내부 lazy import 로 처리하여 api 패키지 임포트 시 외부 라이브러리
    부담을 최소화한다 (테스트가 모듈 로드 시점에 LLM/Celery 의존성을 끌고
    오지 않도록 한다).
  - 메모리 잡 상태(analysis_jobs)/Celery 토글(_USE_CELERY)/_run_analysis 는
    이 모듈에 모아두고 서버는 라우터를 include 만 한다 (api.server 미의존).
  - 테스트는 api.routers.analyze 의 _run_analysis / _USE_CELERY 를
    monkeypatch 하여 백그라운드/Celery 의존성을 끊을 수 있다.

Wave 2-K — Celery/Redis 부수효과 lazy 화:
  - ``_USE_CELERY`` 는 sentinel(``None``) 상태로 초기화되고, 실제 Celery
    경로가 필요한 핸들러에서 ``_ensure_celery_initialized()`` 가 한 번만
    Celery 임포트 + Redis ping 을 시도한다. 실패 시 ``_USE_CELERY=False`` 로
    캐시되어 후속 요청에서 매번 Redis 를 두드리지 않는다.
  - 테스트는 ``_USE_CELERY`` / ``_celery`` / ``run_analysis_task`` 를
    monkeypatch 하여 detector 를 우회하거나, ``_ensure_celery_initialized``
    자체를 stub 으로 교체할 수 있다.
"""

from __future__ import annotations

from threading import Thread

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, UploadFile
from pydantic import BaseModel

from api.auth import verify_api_key
from api.dto.responses import AnalyzeStartResponse
from api.services import analysis_pipeline as _pipeline_service

router = APIRouter()

# 분석 작업 상태 저장 (메모리 — Celery 미사용 시 fallback)
analysis_jobs: dict = {}

# Celery 사용 가능 여부 — sentinel ``None`` 은 '아직 감지하지 않음' 을 의미.
# 첫 사용 시 ``_ensure_celery_initialized()`` 가 ``True`` / ``False`` 로 채운다.
# 테스트가 직접 monkeypatch 한 값(``True`` / ``False``)은 detector 가 그대로
# 존중하여 추가 임포트를 시도하지 않는다.
_USE_CELERY: bool | None = None
_celery = None
run_analysis_task = None


def _ensure_celery_initialized() -> bool:
    """Celery/Redis 가용성을 lazy 하게 감지한다 (idempotent).

    ``_USE_CELERY`` 가 ``None`` 일 때만 ``api.celery_app`` / ``api.tasks`` 임포트
    + Redis ping 을 시도하고, 결과를 모듈 글로벌에 캐시한다. 이후 호출은
    캐시된 값을 즉시 반환한다 — 매 요청마다 Redis 를 두드리지 않는다.

    테스트가 ``_USE_CELERY`` 를 ``True`` / ``False`` 로 monkeypatch 한 경우,
    이 함수는 그 값을 그대로 반환한다 (Celery 임포트 시도하지 않음).

    리셋이 필요한 테스트는 ``_USE_CELERY=None``, ``_celery=None``,
    ``run_analysis_task=None`` 을 monkeypatch 하면 다음 호출 시 다시 감지한다.
    """
    global _USE_CELERY, _celery, run_analysis_task

    if _USE_CELERY is not None:
        return _USE_CELERY

    try:
        from api.celery_app import celery_app as _celery_local
        from api.tasks import run_analysis_task as _task_local
        _celery_local.connection_for_write().ensure_connection(
            max_retries=1, timeout=2
        )
        _celery = _celery_local
        run_analysis_task = _task_local
        _USE_CELERY = True
    except Exception:
        _USE_CELERY = False

    return _USE_CELERY


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
    """백그라운드 분석 실행 — 서비스 ``execute_analysis_job`` 으로 위임한다.

    라우터의 모듈 글로벌 ``analysis_jobs`` 를 그대로 서비스에 넘기므로,
    테스트가 ``analyze_router.analysis_jobs`` 를 monkeypatch 한 dict 가
    그대로 반영된다.
    """
    _pipeline_service.execute_analysis_job(
        jobs=analysis_jobs,
        job_id=job_id, code=code, filename=filename,
        use_llm=use_llm, provider=provider, model=model,
        multi_patch=multi_patch,
    )


@router.post(
    "/api/analyze",
    response_model=AnalyzeStartResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def start_analysis(req: AnalyzeRequest, background_tasks: BackgroundTasks):
    """코드를 제출하여 분석을 시작합니다. Celery 사용 가능 시 task로 제출."""
    if _ensure_celery_initialized():
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
    job_id = _pipeline_service.make_job_id()
    analysis_jobs[job_id] = _pipeline_service.build_initial_job_meta(
        job_id=job_id,
        filename=req.filename,
        code_length=len(req.code),
        use_llm=req.use_llm,
    )

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
    if not _ensure_celery_initialized():
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
    if _ensure_celery_initialized():
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
    job_id = _pipeline_service.make_job_id()
    analysis_jobs[job_id] = _pipeline_service.build_upload_job_meta(
        job_id=job_id, filename=req.filename,
    )

    t = Thread(
        target=_run_analysis,
        args=(job_id, req.code, req.filename, req.use_llm, req.provider, req.model),
    )
    t.start()

    return {"job_id": job_id, "status": "queued"}
