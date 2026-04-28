"""API 서버 엔드포인트 테스트"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 테스트용 API 키 설정 (인증 통과용 — CI 환경변수보다 우선 적용)
os.environ["DALLO_API_KEYS"] = "test-api-key"

from fastapi.testclient import TestClient
from api.server import app

_AUTH_HEADERS = {"X-API-Key": "test-api-key"}
client = TestClient(app)


class TestAPIEndpoints:
    """FastAPI 엔드포인트 테스트"""

    def test_root(self):
        """루트 엔드포인트"""
        r = client.get("/")
        assert r.status_code == 200
        assert r.json()["message"] == "Dallo DevSecOps API"

    def test_stats(self):
        """통계 엔드포인트"""
        r = client.get("/api/stats", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "total_issues" in data
        assert "high" in data
        assert "medium" in data
        assert "low" in data

    def test_vulnerabilities(self):
        """취약점 목록 엔드포인트"""
        r = client.get("/api/vulnerabilities", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "count" in data
        assert "vulnerabilities" in data
        assert isinstance(data["vulnerabilities"], list)

    def test_vulnerabilities_filter_severity(self):
        """취약점 심각도 필터"""
        r = client.get("/api/vulnerabilities?severity=HIGH", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        for v in data["vulnerabilities"]:
            assert v["severity"] == "HIGH"

    def test_vulnerabilities_by_file(self):
        """파일별 취약점 집계"""
        r = client.get("/api/vulnerabilities/by-file", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "files" in data
        for f in data["files"]:
            assert "file" in f
            assert "total" in f

    def test_vulnerabilities_by_type(self):
        """유형별 취약점 집계"""
        r = client.get("/api/vulnerabilities/by-type", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "types" in data
        for t in data["types"]:
            assert "rule_id" in t
            assert "count" in t

    def test_patches(self):
        """패치 목록 엔드포인트"""
        r = client.get("/api/patches", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "count" in data
        assert "patches" in data

    def test_sessions(self):
        """세션 이력 엔드포인트"""
        r = client.get("/api/sessions", headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "count" in data
        assert "sessions" in data

    def test_session_detail_not_found(self):
        """존재하지 않는 세션 상세 조회는 error 메시지를 반환"""
        r = client.get(
            "/api/sessions/__nonexistent_session_id__",
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 200
        assert r.json() == {"error": "Session not found"}

    def test_quick_scan_response_shape(self):
        """POST /api/quick-scan 응답 셰이프 (인증 + 키 집합)"""
        payload = {
            "code": "import hashlib\nh = hashlib.md5(b'x')\n",
            "language": "python",
        }
        r = client.post("/api/quick-scan", json=payload, headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert set(data.keys()) == {"findings", "count", "elapsed_ms", "scan_type"}
        assert data["scan_type"] == "quick"
        assert isinstance(data["findings"], list)
        assert data["count"] == len(data["findings"])
        # 알려진 룰(MD5 해시) 이 탐지되어야 함
        assert any(f.get("rule_id") == "QS-WEAK-HASH" for f in data["findings"])
        for f in data["findings"]:
            assert {"rule_id", "title", "severity", "cwe", "line", "code", "message"} <= set(f.keys())

    def test_quick_scan_requires_auth(self):
        """API 키 없이 호출 시 인증 실패"""
        r = client.post("/api/quick-scan", json={"code": "", "language": "python"})
        assert r.status_code in (401, 403)

    def test_quick_scan_project_response_shape(self):
        """POST /api/quick-scan-project 응답 셰이프"""
        payload = {
            "files": [
                {"path": "a.py", "code": "import hashlib\nhashlib.md5(b'x')\n"},
                {"path": "b.js", "code": "Math.random();\n"},
            ]
        }
        r = client.post("/api/quick-scan-project", json=payload, headers=_AUTH_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert set(data.keys()) == {
            "files", "total_files", "total_findings", "summary", "elapsed_ms",
        }
        assert data["total_files"] == 2
        assert isinstance(data["files"], list)
        assert set(data["summary"].keys()) >= {"HIGH", "MEDIUM", "LOW"}
        for fr in data["files"]:
            assert {"path", "language", "findings", "count"} <= set(fr.keys())
