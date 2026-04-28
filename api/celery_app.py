"""
Celery 인스턴스 초기화 (api/celery_app.py)

Redis를 broker/backend으로 사용하는 Celery 앱.

실행:
    celery -A api.celery_app worker --loglevel=info

환경변수:
    CELERY_BROKER_URL: Redis 브로커 URL (기본: redis://localhost:6379/0)
    CELERY_RESULT_BACKEND: Redis 결과 백엔드 URL (기본: redis://localhost:6379/1)

Wave 2-J: ``sys.path.insert`` 부트스트랩 해킹 제거. ``celery -A api.celery_app``
은 항상 프로젝트 루트(cwd)에서 실행되며, Python 은 cwd 를 자동으로 sys.path 에
추가하므로 ``api.*`` / ``analyzer.*`` / ``db.*`` 임포트가 표준 패키지 탐색으로
해결된다. pytest 환경에서는 pytest.ini 의 ``pythonpath = .`` 가 동일한 역할을 한다.
"""

import os

from dotenv import load_dotenv
load_dotenv()

from celery import Celery

BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
BACKEND_URL = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")

celery_app = Celery(
    "dallo",
    broker=BROKER_URL,
    backend=BACKEND_URL,
    include=["api.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="Asia/Seoul",
    enable_utc=True,
    # 작업 결과 TTL: 24시간
    result_expires=86400,
    # 작업 상태 추적 활성화
    task_track_started=True,
    # worker가 한 번에 하나의 작업만 처리 (분석 작업이 무거우므로)
    worker_concurrency=2,
    worker_prefetch_multiplier=1,
)
