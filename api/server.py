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
from typing import Optional, List
from api.auth import verify_api_key
from api.dto.responses import (
    StatsResponse,
    VulnerabilitiesResponse,
    VulnerabilitiesByFileResponse,
    VulnerabilitiesByTypeResponse,
    PatchesResponse,
    SessionsResponse,
    AnalyzeStartResponse,
)
import json
import re
import os
import sys
import time
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

REPORTS_DIR = "reports"
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


class QuickScanRequest(BaseModel):
    code: str
    language: str = "python"


# ============================================================
# 빠른 스캔 (정규식 기반, 프로세스 실행 없이 즉시 응답)
# ============================================================

QUICK_SCAN_RULES = [
    # SQL Injection
    {
        "id": "QS-SQL-INJECT",
        "title": "SQL Injection 가능성",
        "severity": "HIGH",
        "cwe": "CWE-89",
        "patterns": [
            r'f"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b[^"]*\{',
            r"f'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b[^']*\{",
            r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE)\b.*["\']\s*\+',
            r'\.format\(.*\).*(?:execute|query)',
            r'%s.*(?:execute|query)|(?:execute|query).*%\s',
            r'(?:executeQuery|executeUpdate|execute)\([^)]*\+',
            r'(?:query|exec)\([^)]*\+\s*(?:req\.|user)',
            r'"\s*\+\s*\w+\s*\+\s*".*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)',
        ],
        "languages": ["python", "java", "javascript", "go", "php", "ruby"],
        "message": "사용자 입력이 SQL 쿼리에 직접 삽입될 수 있습니다. 파라미터 바인딩을 사용하세요.",
    },
    # Command Injection
    {
        "id": "QS-CMD-INJECT",
        "title": "Command Injection 가능성",
        "severity": "HIGH",
        "cwe": "CWE-78",
        "patterns": [
            r'os\.system\s*\(\s*f["\']',
            r'os\.system\s*\([^)]*\+',
            r'os\.popen\s*\(\s*f["\']',
            r'subprocess\.(?:call|run|Popen)\s*\(\s*f["\']',
            r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True',
            r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+',
            r'exec\s*\(\s*["\'][^"\']*["\']\s*\+',
            r'child_process.*exec\s*\([^)]*\+',
        ],
        "languages": ["python", "java", "javascript", "go", "c", "cpp"],
        "message": "외부 명령어에 사용자 입력이 삽입될 수 있습니다. shlex.quote() 또는 허용 목록을 사용하세요.",
    },
    # Hardcoded Secrets
    {
        "id": "QS-HARDCODED-SECRET",
        "title": "하드코딩된 인증 정보",
        "severity": "HIGH",
        "cwe": "CWE-798",
        "patterns": [
            r'(?:API_KEY|API_SECRET|SECRET_KEY|ACCESS_KEY|PRIVATE_KEY)\s*=\s*["\'][^"\']{8,}["\']',
            r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
            r'(?:token|TOKEN)\s*=\s*["\'][^"\']{8,}["\']',
            r'(?:sk-|ghp_|gho_|AIzaSy|AKIA)[A-Za-z0-9_\-]{10,}',
            r'(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD)\s*=\s*["\'][^"\']+["\']',
        ],
        "languages": ["python", "java", "javascript", "go", "c", "cpp", "ruby", "php", "kotlin", "rust"],
        "message": "인증 정보가 소스코드에 하드코딩되어 있습니다. 환경변수나 시크릿 매니저를 사용하세요.",
    },
    # Weak Hashing
    {
        "id": "QS-WEAK-HASH",
        "title": "취약한 해시 알고리즘",
        "severity": "MEDIUM",
        "cwe": "CWE-328",
        "patterns": [
            r'hashlib\.(?:md5|sha1)\s*\(',
            r'MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-1|SHA1)["\']',
            r'crypto\.create(?:Hash|Hmac)\s*\(\s*["\'](?:md5|sha1)["\']',
            r'MD5\.Create\(\)',
            r'Digest::(?:MD5|SHA1)',
        ],
        "languages": ["python", "java", "javascript", "ruby", "go", "cpp"],
        "message": "MD5/SHA1은 보안 용도에 부적합합니다. SHA-256 이상 또는 bcrypt/argon2를 사용하세요.",
    },
    # XSS
    {
        "id": "QS-XSS",
        "title": "XSS (Cross-Site Scripting) 가능성",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "patterns": [
            r'res\.send\s*\(\s*["\']<[^>]*["\']\s*\+',
            r'document\.write\s*\(',
            r'\.innerHTML\s*=\s*(?![\s]*["\']<)',
            r'v-html\s*=',
            r'dangerouslySetInnerHTML',
            r'\.write\s*\(\s*["\']<.*\+',
        ],
        "languages": ["javascript", "python", "java", "php", "ruby"],
        "message": "사용자 입력이 HTML에 직접 삽입될 수 있습니다. 이스케이프 처리를 적용하세요.",
    },
    # Insecure Deserialization
    {
        "id": "QS-UNSAFE-DESERIAL",
        "title": "안전하지 않은 역직렬화",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "patterns": [
            r'pickle\.loads?\s*\(',
            r'yaml\.load\s*\([^)]*(?!Loader)',
            r'eval\s*\(\s*(?:request|req|input|user)',
            r'unserialize\s*\(\s*\$',
            r'Marshal\.load\s*\(',
        ],
        "languages": ["python", "java", "javascript", "php", "ruby"],
        "message": "신뢰할 수 없는 데이터의 역직렬화는 원격 코드 실행으로 이어질 수 있습니다.",
    },
    # Path Traversal
    {
        "id": "QS-PATH-TRAVERSAL",
        "title": "경로 탐색 취약점",
        "severity": "MEDIUM",
        "cwe": "CWE-22",
        "patterns": [
            r'open\s*\(\s*(?:f["\']|.*\+|.*format|.*%)',
            r'os\.path\.join\s*\([^)]*(?:request|req|input|user)',
            r'readFile(?:Sync)?\s*\([^)]*(?:req\.|user)',
            r'new\s+File\s*\([^)]*\+',
        ],
        "languages": ["python", "java", "javascript", "go", "php"],
        "message": "사용자 입력이 파일 경로에 사용되면 경로 탐색 공격이 가능합니다.",
    },
    # Insecure Random
    {
        "id": "QS-INSECURE-RANDOM",
        "title": "보안에 부적합한 난수 생성",
        "severity": "LOW",
        "cwe": "CWE-330",
        "patterns": [
            r'random\.random\s*\(',
            r'random\.randint\s*\(',
            r'Math\.random\s*\(',
            r'java\.util\.Random\b',
            r'rand\s*\(\s*\)',
        ],
        "languages": ["python", "java", "javascript", "c", "cpp", "go"],
        "message": "보안 목적(토큰, 키 생성)에는 secrets 모듈이나 crypto.randomBytes를 사용하세요.",
    },
]


def _detect_language(filename: str) -> str:
    ext_map = {
        ".py": "python", ".java": "java", ".js": "javascript", ".jsx": "javascript",
        ".ts": "javascript", ".tsx": "javascript", ".go": "go", ".c": "c",
        ".cpp": "cpp", ".h": "c", ".hpp": "cpp", ".rb": "ruby", ".php": "php",
        ".kt": "kotlin", ".rs": "rust", ".cs": "csharp",
    }
    _, ext = os.path.splitext(filename.lower())
    return ext_map.get(ext, "python")


def _quick_scan(code: str, language: str) -> list:
    """정규식 기반 빠른 취약점 스캔 (밀리초 단위 응답)"""
    findings = []
    lines = code.split("\n")

    for rule in QUICK_SCAN_RULES:
        if language not in rule["languages"]:
            continue
        for pattern in rule["patterns"]:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for line_num, line_text in enumerate(lines, 1):
                    if regex.search(line_text):
                        # 같은 룰이 같은 라인에 중복 탐지되지 않도록
                        already = any(
                            f["rule_id"] == rule["id"] and f["line"] == line_num
                            for f in findings
                        )
                        if not already:
                            findings.append({
                                "rule_id": rule["id"],
                                "title": rule["title"],
                                "severity": rule["severity"],
                                "cwe": rule["cwe"],
                                "line": line_num,
                                "code": line_text.strip(),
                                "message": rule["message"],
                            })
            except re.error:
                continue

    findings.sort(key=lambda f: f["line"])
    return findings


@app.post("/api/quick-scan", dependencies=[Depends(verify_api_key)])
def quick_scan(req: QuickScanRequest):
    """정규식 기반 빠른 스캔 — 프로세스 실행 없이 밀리초 단위 응답"""
    language = req.language or "python"
    start = time.time()
    findings = _quick_scan(req.code, language)
    elapsed_ms = round((time.time() - start) * 1000, 1)
    return {
        "findings": findings,
        "count": len(findings),
        "elapsed_ms": elapsed_ms,
        "scan_type": "quick",
    }


class ProjectScanRequest(BaseModel):
    files: List[dict]  # [{"path": "src/app.py", "code": "..."}]


@app.post("/api/quick-scan-project", dependencies=[Depends(verify_api_key)])
def quick_scan_project(req: ProjectScanRequest):
    """프로젝트 전체 빠른 스캔 — 여러 파일을 한 번에 분석"""
    start = time.time()
    file_results = []
    total_findings = 0
    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for f in req.files:
        fpath = f.get("path", "unknown")
        code = f.get("code", "")
        lang = _detect_language(fpath)
        findings = _quick_scan(code, lang)
        for finding in findings:
            summary[finding["severity"]] = summary.get(finding["severity"], 0) + 1
        total_findings += len(findings)
        file_results.append({
            "path": fpath,
            "language": lang,
            "findings": findings,
            "count": len(findings),
        })

    # 취약점 많은 파일 순으로 정렬
    file_results.sort(key=lambda x: x["count"], reverse=True)
    elapsed_ms = round((time.time() - start) * 1000, 1)

    return {
        "files": file_results,
        "total_files": len(file_results),
        "total_findings": total_findings,
        "summary": summary,
        "elapsed_ms": elapsed_ms,
    }


# ============================================================
# 헬퍼 함수
# ============================================================

def load_bandit_report() -> dict:
    """Bandit 리포트 로드"""
    path = os.path.join(REPORTS_DIR, "bandit_report.json")
    if not os.path.exists(path):
        return {"results": [], "metrics": {"_totals": {}}}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_full_result() -> dict:
    """전체 파이프라인 결과 로드 (LLM 패치 포함)"""
    path = os.path.join(REPORTS_DIR, "full_result.json")
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ============================================================
# API 엔드포인트
# ============================================================

@app.get("/")
def root():
    return {"message": "Dallo DevSecOps API", "version": "1.0.0"}


@app.get("/api/stats", response_model=StatsResponse, response_model_exclude_unset=True, dependencies=[Depends(verify_api_key)])
def get_stats():
    """대시보드 메인 통계 (DB 우선, 폴백: JSON 파일)"""
    stats = db_service.get_stats()
    if stats.get("total_issues", 0) > 0:
        return stats

    # DB에 데이터 없으면 JSON 파일 폴백
    full = load_full_result()
    if full:
        summary = full.get("summary", {})
        return {
            "total_issues": summary.get("total", 0),
            "high": summary.get("high", 0),
            "medium": summary.get("medium", 0),
            "low": summary.get("low", 0),
            "patches_generated": summary.get("patches_generated", 0),
            "patches_verified": summary.get("patches_verified", 0),
            "duration_seconds": full.get("duration_seconds"),
            "session_id": full.get("session_id", ""),
        }

    report = load_bandit_report()
    totals = report.get("metrics", {}).get("_totals", {})
    results = report.get("results", [])
    return {
        "total_issues": len(results),
        "high": totals.get("SEVERITY.HIGH", 0),
        "medium": totals.get("SEVERITY.MEDIUM", 0),
        "low": totals.get("SEVERITY.LOW", 0),
        "patches_generated": 0,
        "patches_verified": 0,
    }


@app.get("/api/vulnerabilities", response_model=VulnerabilitiesResponse, response_model_exclude_unset=True, dependencies=[Depends(verify_api_key)])
def get_vulnerabilities(
    severity: Optional[str] = Query(None, description="HIGH, MEDIUM, LOW"),
    tool: Optional[str] = Query(None, description="bandit, sonarqube"),
    file_path: Optional[str] = Query(None, description="파일 경로 필터"),
):
    """취약점 목록 조회 (필터 지원)"""
    full = load_full_result()

    if full and full.get("vulnerabilities"):
        vulns = full["vulnerabilities"]
    else:
        report = load_bandit_report()
        vulns = []
        for item in report.get("results", []):
            cwe = item.get("issue_cwe", {})
            vulns.append({
                "id": f"vuln_{item.get('test_id', '')}_{item.get('line_number', 0)}",
                "tool": "bandit",
                "rule_id": item.get("test_id", ""),
                "title": item.get("test_name", ""),
                "severity": item.get("issue_severity", ""),
                "confidence": item.get("issue_confidence", ""),
                "description": item.get("issue_text", ""),
                "file_path": item.get("filename", ""),
                "line_number": item.get("line_number", 0),
                "code_snippet": item.get("code", ""),
                "cwe_id": f"CWE-{cwe['id']}" if isinstance(cwe, dict) and cwe.get("id") else None,
                "more_info": item.get("more_info", ""),
            })

    # 필터
    if severity:
        vulns = [v for v in vulns if v.get("severity", "").upper() == severity.upper()]
    if tool:
        vulns = [v for v in vulns if v.get("tool", "").lower() == tool.lower()]
    if file_path:
        vulns = [v for v in vulns if file_path in v.get("file_path", "")]

    return {"count": len(vulns), "vulnerabilities": vulns}


@app.get("/api/vulnerabilities/by-file", response_model=VulnerabilitiesByFileResponse, response_model_exclude_unset=True, dependencies=[Depends(verify_api_key)])
def get_vulnerabilities_by_file():
    """파일별 취약점 수 집계"""
    data = get_vulnerabilities(severity=None, tool=None, file_path=None)
    vulns = data["vulnerabilities"]

    file_counts = {}
    for v in vulns:
        fp = v.get("file_path", "unknown")
        if fp not in file_counts:
            file_counts[fp] = {"file": fp, "high": 0, "medium": 0, "low": 0, "total": 0}
        sev = v.get("severity", "LOW").lower()
        if sev in file_counts[fp]:
            file_counts[fp][sev] += 1
        file_counts[fp]["total"] += 1

    return {"files": list(file_counts.values())}


@app.get("/api/vulnerabilities/by-type", response_model=VulnerabilitiesByTypeResponse, response_model_exclude_unset=True, dependencies=[Depends(verify_api_key)])
def get_vulnerabilities_by_type():
    """취약점 유형별 집계"""
    data = get_vulnerabilities(severity=None, tool=None, file_path=None)
    vulns = data["vulnerabilities"]

    type_counts = {}
    for v in vulns:
        rule = v.get("rule_id", "unknown")
        name = v.get("title", "unknown")
        key = f"{rule}:{name}"
        if key not in type_counts:
            type_counts[key] = {"rule_id": rule, "name": name, "count": 0, "severity": v.get("severity", "")}
        type_counts[key]["count"] += 1

    return {"types": list(type_counts.values())}


@app.get("/api/patches", response_model=PatchesResponse, response_model_exclude_unset=True, dependencies=[Depends(verify_api_key)])
def get_patches():
    """LLM 수정 제안 목록"""
    full = load_full_result()
    patches = full.get("patches", [])

    # 취약점 정보와 매칭
    vulns = {v.get("id"): v for v in full.get("vulnerabilities", [])}
    enriched = []
    for p in patches:
        vuln = vulns.get(p.get("vulnerability_id"), {})
        enriched.append({
            **p,
            "file_path": vuln.get("file_path", ""),
            "line_number": vuln.get("line_number", 0),
            "rule_id": vuln.get("rule_id", ""),
            "severity": vuln.get("severity", ""),
            "title": vuln.get("title", ""),
            "original_code": vuln.get("function_code") or vuln.get("code_snippet", ""),
        })

    return {"count": len(enriched), "patches": enriched}


@app.get("/api/sessions", response_model=SessionsResponse, response_model_exclude_unset=True, dependencies=[Depends(verify_api_key)])
def get_sessions():
    """분석 세션 이력 (DB)"""
    sessions = db_service.get_all_sessions()
    return {"count": len(sessions), "sessions": sessions}


@app.get("/api/sessions/{session_id}", dependencies=[Depends(verify_api_key)])
def get_session_detail(session_id: str):
    """특정 세션 상세 조회"""
    result = db_service.get_analysis_by_session(session_id)
    if not result:
        return {"error": "Session not found"}
    return result


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
