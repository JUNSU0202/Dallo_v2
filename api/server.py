"""
API 서버 (api/server.py) — FastAPI 앱 부트스트랩.

이 파일은 다음만 담당한다 (얇은 부트스트랩):
  1) 환경 로드(dotenv)
  2) FastAPI 앱/CORS 미들웨어/정적 자산 마운트
  3) DB 초기화(init_db) / 업로드 디렉터리 생성을 lifespan 으로 위임
  4) Wave 2 라우터 include
  5) 루트(`/`) 와 React SPA(`/dashboard/*`) 직접 서빙

엔드포인트 로직은 ``api/routers/*.py`` 로 분리되어 있고,
공유 경로/CORS 기본값은 ``api/settings.py`` 가 단일 소스 오브 트루스.

부트스트랩 부수효과(DB 테이블 생성, uploads/ 디렉터리 생성)는 모듈 임포트
시점이 아닌 FastAPI lifespan(애플리케이션 시작) 단계에서 수행된다.
이는 Clean Architecture 의 권장 패턴이며, 모듈을 단순 임포트하는
도구/스크립트(테스트 수집, 라우트 검증 등)에서 의도치 않은 파일 생성/DB
접속이 발생하지 않게 한다. 매 요청마다 init 이 다시 도는 일은 없으며,
``with TestClient(app) as client:`` 또는 uvicorn 로 서비스를 띄울 때 정확히
한 번 실행된다.

실행:
  pip install fastapi uvicorn
  uvicorn api.server:app --reload --port 8000
"""

import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from api.routers.analyze import router as analyze_router
from api.routers.dashboard import router as dashboard_router
from api.routers.dependencies import router as dependencies_router
from api.routers.patch import router as patch_router
from api.routers.quick_scan import router as quick_scan_router
from api.routers.red_blue import router as red_blue_router
from api.routers.report import router as report_router
from api.settings import CORS_ORIGINS, DASHBOARD_DIR, UPLOAD_DIR
from db.models import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """애플리케이션 시작/종료 훅.

    시작 시:
      - DB 테이블 생성 (idempotent — 이미 존재하면 노옵)
      - 업로드/패치 적용 디렉터리 생성 (idempotent)
    종료 시:
      - 정리할 자원 없음 (SessionLocal 은 매 요청마다 닫힘).
    """
    init_db()
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    yield


app = FastAPI(
    title="Dallo DevSecOps API",
    description="보안 분석 결과 조회 API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*", "X-API-Key"],
)

# React 대시보드 빌드 파일 서빙
if os.path.exists(DASHBOARD_DIR):
    app.mount(
        "/assets",
        StaticFiles(directory=os.path.join(DASHBOARD_DIR, "assets")),
        name="static",
    )


# ============================================================
# API 엔드포인트
# ============================================================
# 조회 전용 (대시보드/통계/취약점/패치/세션 GET) — Wave 2-B 분리
app.include_router(dashboard_router)
# 빠른 스캔 (POST /api/quick-scan, /api/quick-scan-project) — Wave 2-C 분리
app.include_router(quick_scan_router)
# 리포트 (GET /api/report/generate|download/{filename}|preview) — Wave 2-D 분리
app.include_router(report_router)
# 의존성 스캔 (GET /api/dependencies, POST /api/dependencies/scan) — Wave 2-E 분리
app.include_router(dependencies_router)
# 패치 적용 (POST /api/apply-patch) — Wave 2-F 분리
app.include_router(patch_router)
# 분석/잡 (POST /api/analyze, GET /api/analyze/status/{task_id},
#         GET /api/analyze/{job_id}, POST /api/analyze/file) — Wave 2-G 분리
app.include_router(analyze_router)
# Red/Blue 종합 요약 (GET /api/red-blue/summary) — Wave 5-C 분리
app.include_router(red_blue_router)


@app.get("/")
def root():
    return {"message": "Dallo DevSecOps API", "version": "1.0.0"}


# ============================================================
# 대시보드 (React SPA) — API 라우트 이후에 배치
# ============================================================

@app.get("/dashboard")
@app.get("/dashboard/{path:path}")
def serve_dashboard(path: str = ""):
    """React 대시보드 서빙"""
    if os.path.exists(DASHBOARD_DIR):
        return FileResponse(os.path.join(DASHBOARD_DIR, "index.html"))
    return {"error": "Dashboard not built. Run: cd dashboard && npm run build"}
