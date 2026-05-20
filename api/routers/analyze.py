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

Wave 3-A — Celery detector 서비스 분리:
  - 실제 가용성 감지 본체는 ``api.services.celery_detector`` 로 옮겨졌다.
    이 모듈의 ``_ensure_celery_initialized()`` 는 서비스의
    ``is_celery_available()`` 결과로 라우터 모듈 글로벌
    (``_USE_CELERY``, ``_celery``, ``run_analysis_task``) 을 동기화하는
    얇은 호환 래퍼로 남는다.
  - 라우터 핸들러는 모듈 글로벌 ``_celery`` / ``run_analysis_task`` 를
    그대로 참조하므로, 기존 테스트가 라우터 모듈에 monkeypatch 하던 표면은
    그대로 작동한다.

Wave 3-D — analysis_jobs 메모리 폴백 정리:
  - 메모리 폴백 dict ``analysis_jobs`` 가 무한 증가할 위험을 줄이기 위해
    ``api.services.analysis_jobs_store.cleanup`` 으로 TTL/캡 정리를 위임한다.
  - 정리 시점은 (1) 새 잡을 메모리에 삽입하기 직전, (2) 잡 상태 조회 직전.
    두 경우 모두 막 만들 잡 / 조회 중인 잡은 ``exclude_ids`` 로 보호된다.
  - ``analysis_jobs`` 자체는 module-level dict 로 유지되어 기존
    ``monkeypatch.setattr(analyze_router, 'analysis_jobs', {})`` 호환을 보존.
"""

from __future__ import annotations

from threading import Thread
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, UploadFile
from pydantic import BaseModel, Field

from api.auth import verify_api_key
from api.dto.responses import AnalyzeStartResponse
from api.services import analysis_jobs_store as _jobs_store
from api.services import analysis_pipeline as _pipeline_service
from api.services import celery_detector as _celery_detector

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

    라우터 모듈 글로벌 ``_USE_CELERY`` 가 ``None`` 이 아니면(테스트가 직접
    True/False 로 세팅한 경우 포함) 그 값을 그대로 반환한다 — 추가 임포트나
    네트워크 시도를 하지 않는다.

    그 외에는 ``api.services.celery_detector.is_celery_available()`` 에 위임
    하고, 결과를 라우터 모듈 글로벌(``_USE_CELERY``, ``_celery``,
    ``run_analysis_task``) 로 동기화한다.
    """
    global _USE_CELERY, _celery, run_analysis_task

    if _USE_CELERY is not None:
        return _USE_CELERY

    if _celery_detector.is_celery_available():
        _celery = _celery_detector.get_celery_app()
        run_analysis_task = _celery_detector.get_run_analysis_task()
        _USE_CELERY = True
    else:
        _USE_CELERY = False

    return _USE_CELERY


class LLMOptimizationRequest(BaseModel):
    """Wave 5-F — optional LLM 입력 최적화 정책.

    필드 셰이프는 ``shared.llm_optimization.LLMOptimizationConfig`` 와 1:1 대응한다.
    빈 객체 ``{}`` 는 명시적인 opt-in 으로 간주되어 모든 default 값으로 채워진다.
    """

    enabled: bool = True
    cve_scope: list[str] = Field(default_factory=list)
    cwe_scope: list[str] = Field(default_factory=list)
    rule_scope: list[str] = Field(default_factory=list)
    max_targets: int = 10
    max_context_chars: int = 2400
    batch_enabled: bool = True
    batch_size: int = 5


class AnalyzeRequest(BaseModel):
    code: str
    filename: str = "uploaded_code.py"
    use_llm: bool = True
    multi_patch: bool = False
    provider: str = "gemini"
    model: str = "gemini-2.0-flash-lite"
    # Wave 5-F: optional LLM 입력 최적화. ``None`` 이면 pre-Wave-5-F 동작 보존
    # (필터/cap 미적용). 명시적으로 ``{}`` 가 들어오면 default config 가 적용된다.
    llm_optimization: Optional[LLMOptimizationRequest] = None
    # Wave 5-M: optional 사용자 추가 지시. ``None`` 이면 LLM 프롬프트에 사용자
    # 섹션이 첨부되지 않아 pre-Wave-5-M 동작이 보존된다. 길이는 보수적으로
    # 2000 자로 제한하여 토큰 폭주/주입 표면을 좁힌다.
    user_prompt: Optional[str] = Field(default=None, max_length=2000)


def _run_analysis(
    job_id: str,
    code: str,
    filename: str,
    use_llm: bool,
    provider: str,
    model: str,
    multi_patch: bool = False,
    llm_optimization=None,
    user_prompt: Optional[str] = None,
):
    """백그라운드 분석 실행 — 서비스 ``execute_analysis_job`` 으로 위임한다.

    라우터의 모듈 글로벌 ``analysis_jobs`` 를 그대로 서비스에 넘기므로,
    테스트가 ``analyze_router.analysis_jobs`` 를 monkeypatch 한 dict 가
    그대로 반영된다.

    Wave 5-F: ``llm_optimization`` 은 ``LLMOptimizationRequest`` 인스턴스 또는
    None 이며, 서비스 → 파이프라인까지 그대로 전파된다.

    Wave 5-M: ``user_prompt`` 는 선택적 문자열 (또는 None) 로 서비스 →
    파이프라인 → LLM agent 까지 그대로 전파된다. 미지정 시 None 이 전달돼
    pre-Wave-5-M 동작을 보존한다. ``None`` 일 때는 inner call 에서 kwarg
    자체를 생략하여, pre-Wave-5-M 시그니처의 monkeypatch 더블 (e.g.
    ``user_prompt`` 를 모르는 fake ``execute_analysis_job``) 과의 호환을
    유지한다. 값이 실제로 제공되면 그대로 forwarding 된다.
    """
    forward_kwargs: dict = {
        "jobs": analysis_jobs,
        "job_id": job_id,
        "code": code,
        "filename": filename,
        "use_llm": use_llm,
        "provider": provider,
        "model": model,
        "multi_patch": multi_patch,
        "llm_optimization": llm_optimization,
    }
    if user_prompt is not None:
        forward_kwargs["user_prompt"] = user_prompt
    _pipeline_service.execute_analysis_job(**forward_kwargs)


@router.post(
    "/api/analyze",
    response_model=AnalyzeStartResponse,
    response_model_exclude_unset=True,
    dependencies=[Depends(verify_api_key)],
)
def start_analysis(req: AnalyzeRequest, background_tasks: BackgroundTasks):
    """코드를 제출하여 분석을 시작합니다. Celery 사용 가능 시 task로 제출.

    Wave 5-F: ``req.llm_optimization`` 가 지정되면 Celery delay / 메모리
    백그라운드 태스크 양쪽으로 그대로 전달된다. Celery 경로는 JSON 직렬화
    호환을 위해 ``model_dump()`` 로 dict 화 해 보낸다. 미지정 시 None 으로
    전달돼 pre-Wave-5-F 동작을 보존한다.
    """
    optimization_payload = (
        req.llm_optimization.model_dump()
        if req.llm_optimization is not None
        else None
    )

    if _ensure_celery_initialized():
        # Celery task로 제출
        task = run_analysis_task.delay(
            code=req.code, filename=req.filename,
            use_llm=req.use_llm, provider=req.provider,
            model=req.model, multi_patch=req.multi_patch,
            llm_optimization=optimization_payload,
            user_prompt=req.user_prompt,
        )
        return {
            "job_id": task.id,
            "status": "queued",
            "message": "분석이 시작되었습니다. (Celery)",
            "backend": "celery",
        }

    # Celery 미사용 fallback — 기존 메모리 방식
    job_id = _pipeline_service.make_job_id()
    # 새 잡 삽입 직전 TTL/캡 정리 — 막 만든 job_id 는 보호.
    _jobs_store.cleanup(analysis_jobs, exclude_ids=(job_id,))
    analysis_jobs[job_id] = _pipeline_service.build_initial_job_meta(
        job_id=job_id,
        filename=req.filename,
        code_length=len(req.code),
        use_llm=req.use_llm,
    )

    # Wave 5-G: positional → keyword forwarding. ``_run_analysis`` 시그니처가
    # 미래에 바뀌어도 우연한 slot 침범 (예: optimization 이 multi_patch 자리에
    # 들어가는 사고) 이 일어나지 않도록 명시적 kwargs 로만 전달한다.
    background_tasks.add_task(
        _run_analysis,
        job_id=job_id,
        code=req.code,
        filename=req.filename,
        use_llm=req.use_llm,
        provider=req.provider,
        model=req.model,
        multi_patch=req.multi_patch,
        llm_optimization=req.llm_optimization,
        user_prompt=req.user_prompt,
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
    # 조회 직전 TTL/캡 정리 — 조회 중인 job_id 는 보호. 정리 헬퍼는
    # 시간/IO 가 없는 in-memory 작업이라 hot path 에서도 부담이 없다.
    _jobs_store.cleanup(analysis_jobs, exclude_ids=(job_id,))
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
    # 새 잡 삽입 직전 TTL/캡 정리 — 막 만든 job_id 는 보호.
    _jobs_store.cleanup(analysis_jobs, exclude_ids=(job_id,))
    analysis_jobs[job_id] = _pipeline_service.build_upload_job_meta(
        job_id=job_id, filename=req.filename,
    )

    # Wave 5-G: positional ``args=(...)`` → ``kwargs={...}`` 로 전환. 메모리
    # 폴백 경로와 동일한 keyword 계약을 유지하고, ``multi_patch`` /
    # ``llm_optimization`` 은 default-equivalent 값 (False / None) 으로 명시
    # 전달한다.
    t = Thread(
        target=_run_analysis,
        kwargs={
            "job_id": job_id,
            "code": req.code,
            "filename": req.filename,
            "use_llm": req.use_llm,
            "provider": req.provider,
            "model": req.model,
            "multi_patch": False,
            "llm_optimization": None,
            "user_prompt": None,
        },
    )
    t.start()

    return {"job_id": job_id, "status": "queued"}
