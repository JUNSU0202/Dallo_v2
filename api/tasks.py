"""
Celery 분석 태스크 (api/tasks.py)

분석 파이프라인을 Celery task로 래핑합니다.
실제 로직은 analyzer.pipeline.execute_pipeline()에 위임합니다.

Wave 2-J: ``sys.path.insert`` 부트스트랩 해킹 제거.
``celery -A api.celery_app`` (which loads ``api.tasks`` via ``include``) 는 항상
프로젝트 루트에서 실행되므로, cwd 가 sys.path 에 자동 포함되어 ``analyzer.*`` /
``api.*`` 임포트가 표준 패키지 탐색으로 해결된다.
"""

from api.celery_app import celery_app


@celery_app.task(bind=True, name="dallo.analyze")
def run_analysis_task(self, code: str, filename: str, use_llm: bool = True,
                      provider: str = "gemini", model: str = "gemini-2.0-flash-lite",
                      multi_patch: bool = False):
    """
    Celery task: 분석 파이프라인 실행

    self.update_state()를 통해 진행 상태를 Redis에 기록합니다.
    실제 분석 로직은 analyzer.pipeline에 위임합니다.
    """
    from analyzer.pipeline import execute_pipeline

    job_id = self.request.id

    def on_progress(step: str):
        self.update_state(state="PROGRESS", meta={"step": step, "job_id": job_id})

    try:
        result = execute_pipeline(
            job_id=job_id, code=code, filename=filename,
            use_llm=use_llm, provider=provider, model=model,
            multi_patch=multi_patch, on_progress=on_progress,
        )

        return {
            "status": "completed",
            "result": result.result_data,
            "job_id": job_id,
        }

    except ValueError as e:
        return {"status": "failed", "error": str(e), "job_id": job_id}
    except Exception as e:
        return {"status": "failed", "error": str(e), "job_id": job_id}
