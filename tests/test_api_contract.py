"""
Wave 1-B: API 응답 셰이프 계약 테스트 (tests/test_api_contract.py)

대시보드가 의존하는 공개 JSON 응답의 구조(키 집합)를 동결합니다.
이후의 클린 아키텍처 리팩터링이 실수로 응답 셰이프를 깨뜨리는 것을 방지합니다.

원칙:
- 정확한 카운트는 검증하지 않습니다 (DB/리포트 상태에 의존하지 않도록).
- 데이터가 비어 있어도 최상위 키는 항상 존재해야 합니다.
- 데이터가 존재할 때(시드/모킹)에만 컬렉션 항목의 필수 키를 검증합니다.
"""

import os
import sys
from datetime import datetime, timezone
from contextlib import contextmanager

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 테스트용 인증/암호화 키 (CI 환경변수보다 우선)
os.environ["DALLO_API_KEYS"] = "test-api-key"
os.environ.setdefault("DALLO_ENCRYPTION_KEY", "test-key")

from fastapi.testclient import TestClient
from api import server as api_server
from api.server import app
from db import service as db_service
from db.models import SessionLocal, AnalysisRun, Vulnerability, Patch


_AUTH_HEADERS = {"X-API-Key": "test-api-key"}
client = TestClient(app)


# ============================================================
# 픽스처: 합성 분석 결과 (full_result.json 셰이프와 동일)
# ============================================================

def _synthetic_full_result(session_id: str) -> dict:
    """db_service.save_analysis가 받는 셰이프와 동일한 합성 데이터."""
    return {
        "session_id": session_id,
        "repo": "test/contract",
        "pr_number": 1,
        "commit_sha": "deadbeef",
        "branch": "main",
        "summary": {
            "total": 2, "high": 1, "medium": 1, "low": 0,
            "patches_generated": 1, "patches_verified": 1,
        },
        "vulnerabilities": [
            {
                "id": "vuln_B608_10",
                "tool": "bandit",
                "rule_id": "B608",
                "severity": "HIGH",
                "confidence": "HIGH",
                "title": "SQL Injection",
                "description": "f-string SQL 사용",
                "cwe_id": "CWE-89",
                "file_path": "app.py",
                "line_number": 10,
                "code_snippet": "query = f'SELECT * FROM u WHERE id={uid}'",
                "function_code": "def get(): query = f'SELECT * FROM u WHERE id={uid}'",
                "more_info": "https://example.test/B608",
            },
            {
                "id": "vuln_B303_30",
                "tool": "bandit",
                "rule_id": "B303",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "title": "Weak Hash",
                "description": "MD5 사용",
                "cwe_id": "CWE-328",
                "file_path": "util.py",
                "line_number": 30,
                "code_snippet": "hashlib.md5(data)",
                "function_code": "def h(): hashlib.md5(data)",
                "more_info": "",
            },
        ],
        "patches": [
            {
                "vulnerability_id": "vuln_B608_10",
                "fixed_code": "cur.execute('SELECT * FROM u WHERE id=%s', (uid,))",
                "explanation": "파라미터 바인딩으로 변경",
                "fix_type": "recommended",
                "status": "verified",
                "syntax_valid": True,
                "test_passed": True,
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        ],
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": 1.23,
    }


@pytest.fixture
def full_result_data():
    """JSON 폴백 경로(load_full_result)에서 사용할 합성 데이터."""
    return _synthetic_full_result(session_id="contract_test_session_json")


@pytest.fixture
def patched_full_result(monkeypatch, full_result_data):
    """api.server.load_full_result를 합성 데이터로 모킹."""
    monkeypatch.setattr(api_server, "load_full_result", lambda: full_result_data)
    return full_result_data


@contextmanager
def _seeded_db_session(session_id: str):
    """DB에 세션을 시드하고 종료 후 정리."""
    data = _synthetic_full_result(session_id=session_id)
    db_service.save_analysis(data)
    try:
        yield data
    finally:
        with SessionLocal() as db:
            run = db.query(AnalysisRun).filter_by(session_id=session_id).first()
            if run:
                vulns = db.query(Vulnerability).filter_by(run_id=run.id).all()
                for v in vulns:
                    for p in list(v.patches):
                        db.delete(p)
                    db.delete(v)
                db.delete(run)
                db.commit()


@pytest.fixture
def seeded_db():
    with _seeded_db_session("contract_test_session_db") as data:
        yield data


# ============================================================
# 유틸: 응답이 dict이고 모든 요구 키가 존재하는지 확인
# ============================================================

def _assert_keys(obj, required, where=""):
    assert isinstance(obj, dict), f"{where}: dict 아님 ({type(obj).__name__})"
    missing = [k for k in required if k not in obj]
    assert not missing, f"{where}: 키 누락 {missing} (실제 키: {sorted(obj.keys())})"


# ============================================================
# /api/stats
# ============================================================

class TestStatsContract:
    """GET /api/stats 응답 셰이프"""

    REQUIRED_TOP = {"total_issues", "high", "medium", "low",
                    "patches_generated", "patches_verified"}

    def test_stats_top_level_keys_when_empty(self):
        """DB가 비어 있어도 최소 통계 키는 존재해야 함."""
        r = client.get("/api/stats", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        _assert_keys(data, self.REQUIRED_TOP, where="/api/stats (empty)")
        # 카운트 타입은 숫자
        for k in self.REQUIRED_TOP:
            assert isinstance(data[k], int), f"{k}는 int여야 함: {type(data[k]).__name__}"

    def test_stats_with_db_data_includes_session_keys(self, seeded_db):
        """DB에 데이터가 있을 때 session_id/total_sessions까지 포함."""
        r = client.get("/api/stats", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        _assert_keys(data, self.REQUIRED_TOP | {"session_id", "total_sessions"},
                     where="/api/stats (with db)")
        assert isinstance(data["session_id"], str)
        assert isinstance(data["total_sessions"], int)


# ============================================================
# /api/vulnerabilities
# ============================================================

class TestVulnerabilitiesContract:
    """GET /api/vulnerabilities 응답 셰이프"""

    REQUIRED_TOP = {"count", "vulnerabilities"}
    # 대시보드가 의존하는 핵심 필드
    REQUIRED_ITEM = {"id", "tool", "rule_id", "severity", "title",
                     "file_path", "line_number", "code_snippet"}

    def test_top_level_keys_when_empty(self):
        r = client.get("/api/vulnerabilities", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        _assert_keys(data, self.REQUIRED_TOP, where="/api/vulnerabilities (empty)")
        assert isinstance(data["count"], int)
        assert isinstance(data["vulnerabilities"], list)

    def test_item_keys_when_data_exists(self, patched_full_result):
        """full_result에 데이터가 있을 때 항목 셰이프 검증."""
        r = client.get("/api/vulnerabilities", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        _assert_keys(data, self.REQUIRED_TOP, where="/api/vulnerabilities")
        assert data["count"] >= 1
        for i, v in enumerate(data["vulnerabilities"]):
            _assert_keys(v, self.REQUIRED_ITEM, where=f"vulnerabilities[{i}]")
            assert v["severity"] in ("HIGH", "MEDIUM", "LOW")
            assert isinstance(v["line_number"], int)

    def test_severity_filter_preserves_shape(self, patched_full_result):
        """severity 필터를 걸어도 셰이프 동일."""
        r = client.get("/api/vulnerabilities?severity=HIGH", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        _assert_keys(data, self.REQUIRED_TOP, where="/api/vulnerabilities?severity")
        for v in data["vulnerabilities"]:
            assert v["severity"] == "HIGH"


# ============================================================
# /api/vulnerabilities/by-file
# ============================================================

class TestVulnerabilitiesByFileContract:
    """GET /api/vulnerabilities/by-file 응답 셰이프"""

    REQUIRED_TOP = {"files"}
    REQUIRED_ITEM = {"file", "high", "medium", "low", "total"}

    def test_top_level_keys_when_empty(self):
        r = client.get("/api/vulnerabilities/by-file", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        _assert_keys(data, self.REQUIRED_TOP, where="/api/vulnerabilities/by-file (empty)")
        assert isinstance(data["files"], list)

    def test_item_keys_when_data_exists(self, patched_full_result):
        r = client.get("/api/vulnerabilities/by-file", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert len(data["files"]) >= 1
        for i, f in enumerate(data["files"]):
            _assert_keys(f, self.REQUIRED_ITEM, where=f"files[{i}]")
            assert isinstance(f["total"], int)
            assert isinstance(f["high"], int)
            assert isinstance(f["medium"], int)
            assert isinstance(f["low"], int)


# ============================================================
# /api/vulnerabilities/by-type
# ============================================================

class TestVulnerabilitiesByTypeContract:
    """GET /api/vulnerabilities/by-type 응답 셰이프"""

    REQUIRED_TOP = {"types"}
    REQUIRED_ITEM = {"rule_id", "name", "count", "severity"}

    def test_top_level_keys_when_empty(self):
        r = client.get("/api/vulnerabilities/by-type", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        _assert_keys(data, self.REQUIRED_TOP, where="/api/vulnerabilities/by-type (empty)")
        assert isinstance(data["types"], list)

    def test_item_keys_when_data_exists(self, patched_full_result):
        r = client.get("/api/vulnerabilities/by-type", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert len(data["types"]) >= 1
        for i, t in enumerate(data["types"]):
            _assert_keys(t, self.REQUIRED_ITEM, where=f"types[{i}]")
            assert isinstance(t["count"], int)


# ============================================================
# /api/patches
# ============================================================

class TestPatchesContract:
    """GET /api/patches 응답 셰이프"""

    REQUIRED_TOP = {"count", "patches"}
    # 대시보드 Diff/카드 뷰가 사용하는 필수 필드
    REQUIRED_ITEM = {
        "vulnerability_id", "fixed_code", "explanation", "fix_type", "status",
        "file_path", "line_number", "rule_id", "severity", "title", "original_code",
    }

    def test_top_level_keys_when_empty(self):
        r = client.get("/api/patches", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        _assert_keys(data, self.REQUIRED_TOP, where="/api/patches (empty)")
        assert isinstance(data["count"], int)
        assert isinstance(data["patches"], list)

    def test_item_keys_when_data_exists(self, patched_full_result):
        r = client.get("/api/patches", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["count"] >= 1
        for i, p in enumerate(data["patches"]):
            _assert_keys(p, self.REQUIRED_ITEM, where=f"patches[{i}]")
            assert p["fix_type"] in ("minimal", "recommended", "structural")
            assert isinstance(p["line_number"], int)


# ============================================================
# /api/sessions
# ============================================================

class TestSessionsContract:
    """GET /api/sessions 응답 셰이프"""

    REQUIRED_TOP = {"count", "sessions"}
    REQUIRED_ITEM = {
        "session_id", "repo", "pr_number", "commit_sha",
        "total_issues", "high_count", "medium_count", "low_count",
        "patches_generated", "patches_verified",
        "started_at", "completed_at", "duration_seconds",
    }

    def test_top_level_keys_when_empty(self):
        r = client.get("/api/sessions", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        _assert_keys(data, self.REQUIRED_TOP, where="/api/sessions (empty)")
        assert isinstance(data["count"], int)
        assert isinstance(data["sessions"], list)

    def test_item_keys_when_data_exists(self, seeded_db):
        r = client.get("/api/sessions", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["count"] >= 1
        for i, s in enumerate(data["sessions"]):
            _assert_keys(s, self.REQUIRED_ITEM, where=f"sessions[{i}]")
            assert isinstance(s["total_issues"], int)
            assert isinstance(s["pr_number"], int)


# ============================================================
# /api/analyze (use_llm=False, 백그라운드 작업은 노옵으로 모킹)
# ============================================================

class TestAnalyzeContract:
    """POST /api/analyze 즉시 응답 셰이프 (LLM/네트워크 호출 없음)"""

    REQUIRED_TOP = {"job_id", "status", "message", "backend"}

    def test_analyze_immediate_response_shape(self, monkeypatch):
        """
        /api/analyze는 백그라운드 분석을 큐잉하고 즉시 반환합니다.
        LLM/외부 호출 없이 즉시 응답 셰이프만 검증하기 위해
        백그라운드 분석 함수를 노옵으로 대체합니다.
        """
        # 백그라운드에서 실제 정적 분석 파이프라인이 실행되는 것을 막음
        monkeypatch.setattr(api_server, "_run_analysis", lambda *a, **kw: None)

        payload = {
            "code": "print('hello')\n",
            "filename": "sample.py",
            "use_llm": False,  # LLM 호출 없음
        }
        r = client.post("/api/analyze", json=payload, headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        data = r.json()
        _assert_keys(data, self.REQUIRED_TOP, where="/api/analyze")
        assert isinstance(data["job_id"], str) and data["job_id"]
        assert data["status"] in ("queued", "PENDING")
        assert data["backend"] in ("memory", "celery")
