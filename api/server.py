"""
API 서버 (api/server.py)

React 대시보드가 이 API를 호출하여 데이터를 가져갑니다.

실행:
  pip install fastapi uvicorn
  uvicorn api.server:app --reload --port 8000
"""

from fastapi import FastAPI, Query, UploadFile, File, Form, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
from api.auth import verify_api_key
from api.dto.responses import AnalyzeStartResponse
from api.result_sources import (
    REPORTS_DIR,
    load_bandit_report,
    load_full_result,
)
from api.routers.dashboard import router as dashboard_router
from api.routers.quick_scan import router as quick_scan_router
import json
import os
import sys
import uuid
from datetime import datetime

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

# 분석 작업 상태 저장 (메모리 — Celery 미사용 시 fallback)
analysis_jobs = {}

# Celery 사용 가능 여부 감지
_USE_CELERY = False
try:
    from api.celery_app import celery_app as _celery
    from api.tasks import run_analysis_task
    # Redis 연결 확인
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


class ApplyPatchRequest(BaseModel):
    original_code: str
    fixed_code: str
    filename: str
    vulnerability_id: str
    fix_type: str = "recommended"
    github_repo: str = ""     # 사용자의 GitHub 레포 (owner/repo)
    github_token: str = ""    # 사용자의 GitHub 토큰


# ============================================================
# API 엔드포인트
# ============================================================

# 조회 전용 라우터 (대시보드/통계/취약점/패치/세션 GET) — Wave 2-B 분리
app.include_router(dashboard_router)
# 빠른 스캔 라우터 (POST /api/quick-scan, /api/quick-scan-project) — Wave 2-C 분리
app.include_router(quick_scan_router)


@app.get("/")
def root():
    return {"message": "Dallo DevSecOps API", "version": "1.0.0"}


# ============================================================
# 코드 분석 실행 API
# ============================================================

def _run_analysis(job_id: str, code: str, filename: str, use_llm: bool, provider: str, model: str, multi_patch: bool = False):
    """백그라운드에서 분석 파이프라인 실행 (analyzer.pipeline에 위임)"""
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


@app.post("/api/analyze", response_model=AnalyzeStartResponse, response_model_exclude_unset=True, dependencies=[Depends(verify_api_key)])
def start_analysis(req: AnalyzeRequest, background_tasks: BackgroundTasks):
    """코드를 제출하여 분석을 시작합니다. Celery 사용 가능 시 task로 제출."""
    if _USE_CELERY:
        # Celery task로 제출
        task = run_analysis_task.delay(
            code=req.code, filename=req.filename,
            use_llm=req.use_llm, provider=req.provider,
            model=req.model, multi_patch=req.multi_patch,
        )
        return {"job_id": task.id, "status": "queued", "message": "분석이 시작되었습니다. (Celery)", "backend": "celery"}

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

    return {"job_id": job_id, "status": "queued", "message": "분석이 시작되었습니다.", "backend": "memory"}


@app.get("/api/analyze/status/{task_id}", dependencies=[Depends(verify_api_key)])
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


@app.get("/api/analyze/{job_id}", dependencies=[Depends(verify_api_key)])
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


@app.post("/api/apply-patch", dependencies=[Depends(verify_api_key)])
def apply_patch(req: ApplyPatchRequest):
    """
    수정안을 적용합니다.
    1. 수정 코드로 새 브랜치 생성
    2. 해당 브랜치에 커밋
    3. Pull Request 자동 생성
    4. Diff도 함께 반환
    """
    import difflib
    import base64
    import requests as http_requests

    # diff 생성
    original_lines = req.original_code.splitlines(keepends=True)
    fixed_lines = req.fixed_code.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        original_lines, fixed_lines,
        fromfile=f"a/{req.filename}",
        tofile=f"b/{req.filename}",
        lineterm="",
    ))

    # 로컬에도 저장
    safe_filename = req.filename.replace("/", "_").replace("\\", "_")
    applied_dir = os.path.join(UPLOAD_DIR, "applied")
    os.makedirs(applied_dir, exist_ok=True)
    with open(os.path.join(applied_dir, safe_filename), "w", encoding="utf-8") as f:
        f.write(req.fixed_code)

    result = {
        "status": "applied_local",
        "filename": req.filename,
        "vulnerability_id": req.vulnerability_id,
        "fix_type": req.fix_type,
        "diff": "\n".join(diff),
        "original_lines": len(original_lines),
        "fixed_lines": len(fixed_lines),
        "pr_url": None,
        "branch": None,
    }

    # GitHub 브랜치 + PR 생성 시도
    # 사용자가 입력한 레포/토큰 우선, 없으면 서버 환경변수 폴백
    token = req.github_token or os.environ.get("GITHUB_TOKEN", "")
    repo = req.github_repo or os.environ.get("GITHUB_REPOSITORY", "")

    if not token or not repo:
        result["message"] = "로컬 저장 완료 (GITHUB_TOKEN 미설정 — PR 생성 스킵)"
        return result

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    api_base = f"https://api.github.com/repos/{repo}"

    try:
        # 1. main 브랜치의 최신 SHA 가져오기
        ref_resp = http_requests.get(f"{api_base}/git/ref/heads/main", headers=headers, timeout=10)
        if ref_resp.status_code != 200:
            result["message"] = f"main 브랜치 조회 실패: {ref_resp.status_code}"
            return result
        main_sha = ref_resp.json()["object"]["sha"]

        # 2. 새 브랜치 생성 (fix/vuln_id_timestamp)
        branch_name = f"fix/{req.vulnerability_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        create_ref = http_requests.post(
            f"{api_base}/git/refs",
            headers=headers,
            json={"ref": f"refs/heads/{branch_name}", "sha": main_sha},
            timeout=10,
        )
        if create_ref.status_code not in (200, 201):
            result["message"] = f"브랜치 생성 실패: {create_ref.status_code}"
            return result

        # 3. 파일이 기존에 있는지 확인 (있으면 SHA 필요)
        file_path = req.filename
        file_resp = http_requests.get(
            f"{api_base}/contents/{file_path}?ref={branch_name}",
            headers=headers, timeout=10,
        )
        file_sha = file_resp.json().get("sha") if file_resp.status_code == 200 else None

        # 4. 수정된 코드를 브랜치에 커밋
        content_b64 = base64.b64encode(req.fixed_code.encode("utf-8")).decode("utf-8")
        commit_data = {
            "message": f"fix: {req.vulnerability_id} 보안 취약점 수정 ({req.fix_type})\n\nDallo AI 자동 수정안 적용",
            "content": content_b64,
            "branch": branch_name,
        }
        if file_sha:
            commit_data["sha"] = file_sha

        commit_resp = http_requests.put(
            f"{api_base}/contents/{file_path}",
            headers=headers,
            json=commit_data,
            timeout=10,
        )
        if commit_resp.status_code not in (200, 201):
            result["message"] = f"커밋 실패: {commit_resp.status_code} {commit_resp.text[:200]}"
            return result

        # 5. Pull Request 생성
        pr_body = f"""## 🤖 Dallo AI 보안 수정안

**취약점**: `{req.vulnerability_id}`
**수정 유형**: {req.fix_type}
**파일**: `{req.filename}`

### Diff
```diff
{chr(10).join(diff)}
```

---
*🛡️ Dallo DevSecOps — AI 자동 수정안*
"""
        pr_resp = http_requests.post(
            f"{api_base}/pulls",
            headers=headers,
            json={
                "title": f"🤖 fix: {req.vulnerability_id} 보안 취약점 수정",
                "head": branch_name,
                "base": "main",
                "body": pr_body,
            },
            timeout=10,
        )

        if pr_resp.status_code in (200, 201):
            pr_data = pr_resp.json()
            result["status"] = "pr_created"
            result["pr_url"] = pr_data["html_url"]
            result["pr_number"] = pr_data["number"]
            result["branch"] = branch_name
            result["message"] = f"PR #{pr_data['number']} 생성 완료"
        else:
            result["status"] = "committed"
            result["branch"] = branch_name
            result["message"] = f"브랜치 커밋 완료, PR 생성 실패: {pr_resp.status_code}"

    except Exception as e:
        result["message"] = f"GitHub 연동 오류: {str(e)}"

    return result


@app.post("/api/analyze/file", dependencies=[Depends(verify_api_key)])
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

    from threading import Thread
    t = Thread(target=_run_analysis, args=(job_id, req.code, req.filename, req.use_llm, req.provider, req.model))
    t.start()

    return {"job_id": job_id, "status": "queued"}


# ============================================================
# 리포트 생성 API
# ============================================================

@app.get("/api/report/generate", dependencies=[Depends(verify_api_key)])
def generate_report(
    fmt: str = Query("html", description="md, html, both"),
    session_id: Optional[str] = Query(None, description="세션 ID (없으면 최신)"),
    include_deps: bool = Query(False, description="의존성 스캔 포함"),
):
    """분석 리포트를 생성하고 다운로드 경로를 반환합니다."""
    from reports.report_generator import ReportGenerator

    # 데이터 로드
    if session_id:
        data = db_service.get_analysis_by_session(session_id)
    else:
        data = db_service.get_latest_analysis()

    if not data:
        full = load_full_result()
        if not full:
            return {"error": "분석 데이터가 없습니다. 먼저 코드 분석을 실행하세요."}
        data = full

    # 의존성 스캔 포함
    deps_data = None
    if include_deps:
        try:
            from analyzer.dependency_scanner import DependencyScanner
            scanner = DependencyScanner()
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            deps_data = {"results": [r.to_dict() for r in scanner.scan(project_root)]}
        except Exception:
            pass

    gen = ReportGenerator()
    result = gen.save_report(data, output_dir=REPORTS_DIR, fmt=fmt, include_deps=deps_data)

    return {
        "status": "generated",
        "files": result,
        "download_urls": {
            k: f"/api/report/download/{os.path.basename(v)}"
            for k, v in result.items()
        },
    }


@app.get("/api/report/download/{filename}", dependencies=[Depends(verify_api_key)])
def download_report(filename: str):
    """생성된 리포트 파일을 다운로드합니다."""
    safe_name = filename.replace("/", "_").replace("\\", "_")
    path = os.path.join(REPORTS_DIR, safe_name)
    if not os.path.exists(path):
        return {"error": "리포트 파일을 찾을 수 없습니다."}

    media_type = "text/html" if path.endswith(".html") else "text/markdown"
    return FileResponse(path, media_type=media_type, filename=safe_name)


@app.get("/api/report/preview", dependencies=[Depends(verify_api_key)])
def preview_report(
    session_id: Optional[str] = Query(None),
    include_deps: bool = Query(False),
):
    """리포트를 생성하고 HTML 내용을 바로 반환합니다 (미리보기)."""
    from reports.report_generator import ReportGenerator

    if session_id:
        data = db_service.get_analysis_by_session(session_id)
    else:
        data = db_service.get_latest_analysis()

    if not data:
        full = load_full_result()
        if not full:
            return {"error": "분석 데이터가 없습니다."}
        data = full

    deps_data = None
    if include_deps:
        try:
            from analyzer.dependency_scanner import DependencyScanner
            scanner = DependencyScanner()
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            deps_data = {"results": [r.to_dict() for r in scanner.scan(project_root)]}
        except Exception:
            pass

    gen = ReportGenerator()
    html = gen.generate_html(data, deps_data)
    md = gen.generate_markdown(data, deps_data)

    return {"html": html, "markdown": md}


# ============================================================
# 의존성 취약점 분석 API
# ============================================================

class DependencyScanRequest(BaseModel):
    requirements_text: str = ""      # requirements.txt 내용
    package_json_text: str = ""      # package.json 내용
    project_path: str = ""           # 프로젝트 경로 (서버 로컬)


@app.post("/api/dependencies/scan", dependencies=[Depends(verify_api_key)])
def scan_dependencies(req: DependencyScanRequest):
    """의존성 취약점을 스캔합니다."""
    from analyzer.dependency_scanner import DependencyScanner
    scanner = DependencyScanner()

    results = []
    if req.requirements_text:
        results.append(scanner.scan_requirements_text(req.requirements_text).to_dict())
    elif req.package_json_text:
        results.append(scanner.scan_package_json_text(req.package_json_text).to_dict())
    elif req.project_path and os.path.exists(req.project_path):
        results = [r.to_dict() for r in scanner.scan(req.project_path)]
    else:
        # 현재 프로젝트 스캔
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results = [r.to_dict() for r in scanner.scan(project_root)]

    return {"results": results}


@app.get("/api/dependencies", dependencies=[Depends(verify_api_key)])
def get_dependencies():
    """현재 프로젝트의 의존성 스캔 결과를 반환합니다."""
    from analyzer.dependency_scanner import DependencyScanner
    scanner = DependencyScanner()
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    results = [r.to_dict() for r in scanner.scan(project_root)]
    return {"results": results}


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
