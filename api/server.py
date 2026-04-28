"""
API 서버 (api/server.py)

React 대시보드가 이 API를 호출하여 데이터를 가져갑니다.

실행:
  pip install fastapi uvicorn
  uvicorn api.server:app --reload --port 8000
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from api.routers.analyze import router as analyze_router
from api.routers.dashboard import router as dashboard_router
from api.routers.dependencies import router as dependencies_router
from api.routers.patch import router as patch_router
from api.routers.quick_scan import router as quick_scan_router
from api.routers.report import router as report_router
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv()

app = FastAPI(
    title="Dallo DevSecOps API",
    description="보안 분석 결과 조회 API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*", "X-API-Key"],
)

# React 대시보드 빌드 파일 서빙
DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard", "dist")
if os.path.exists(DASHBOARD_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(DASHBOARD_DIR, "assets")), name="static")

from db.models import init_db
from db import service as db_service

# DB 초기화 (테이블 생성)
init_db()

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ============================================================
# API 엔드포인트
# ============================================================

# 조회 전용 라우터 (대시보드/통계/취약점/패치/세션 GET) — Wave 2-B 분리
app.include_router(dashboard_router)
# 빠른 스캔 라우터 (POST /api/quick-scan, /api/quick-scan-project) — Wave 2-C 분리
app.include_router(quick_scan_router)
# 리포트 라우터 (GET /api/report/generate|download/{filename}|preview) — Wave 2-D 분리
app.include_router(report_router)
# 의존성 스캔 라우터 (GET /api/dependencies, POST /api/dependencies/scan) — Wave 2-E 분리
app.include_router(dependencies_router)
# 패치 적용 라우터 (POST /api/apply-patch) — Wave 2-F 분리
app.include_router(patch_router)
# 분석/잡 라우터 (POST /api/analyze, GET /api/analyze/status/{task_id},
#                GET /api/analyze/{job_id}, POST /api/analyze/file) — Wave 2-G 분리
app.include_router(analyze_router)


@app.get("/")
def root():
    return {"message": "Dallo DevSecOps API", "version": "1.0.0"}


# ============================================================
# 코드 분석 실행 API
# ============================================================
# Wave 2-G: POST /api/analyze, GET /api/analyze/status/{task_id},
# GET /api/analyze/{job_id}, POST /api/analyze/file 는
# api/routers/analyze.py 로 이동되었다 (위 include_router 참조).


# ============================================================
# 패치 적용 API
# ============================================================
# Wave 2-F: POST /api/apply-patch 는 api/routers/patch.py 로 이동되었다
# (위 include_router 참조).


# ============================================================
# 리포트 생성 API
# ============================================================
# Wave 2-D: GET /api/report/generate|download/{filename}|preview 는
# api/routers/report.py 로 이동되었다 (위 include_router 참조).


# ============================================================
# 의존성 취약점 분석 API
# ============================================================
# Wave 2-E: GET /api/dependencies, POST /api/dependencies/scan 는
# api/routers/dependencies.py 로 이동되었다 (위 include_router 참조).


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
