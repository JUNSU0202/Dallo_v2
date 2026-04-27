"""
CI 게이트 골든/회귀 테스트 (tests/test_ci_gate_golden.py)

기존 test_ci_gate.py가 다루지 않는 출력 형식 안정성, JSON 변형,
risk_level 우선순위 규칙, YAML/환경변수 설정 우선순위를 보호한다.

큰 리팩터링 전에 동작이 보존되는지 확인할 수 있는 안전망 역할을 한다.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.ci_gate import check_gate, load_gate_config


def _write_result(tmp_path, payload):
    path = tmp_path / "result.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


class TestCIGateOutputShape:
    """게이트 메시지 형식 안정성 — PR 코멘트/CI 로그 파싱이 의존."""

    def test_pass_message_includes_thresholds_and_counts(self, tmp_path):
        path = _write_result(tmp_path, {"vulnerabilities": [
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
        ]})
        passed, msg = check_gate(path, {"critical_threshold": 1, "high_threshold": 5})
        assert passed is True
        assert "Gate Status: PASSED" in msg
        assert "총 취약점: 2개" in msg
        assert "CRITICAL: 0" in msg and "HIGH: 0" in msg
        assert "MEDIUM: 1" in msg and "LOW: 1" in msg
        assert "임계값" in msg

    def test_fail_message_lists_each_reason(self, tmp_path):
        vulns = [{"severity": "CRITICAL"}] + [{"severity": "HIGH"} for _ in range(6)]
        path = _write_result(tmp_path, {"vulnerabilities": vulns})
        passed, msg = check_gate(path, {"critical_threshold": 1, "high_threshold": 5})
        assert passed is False
        assert "Gate Status: FAILED" in msg
        # 두 가지 실패 사유 모두 표시되어야 함
        assert "CRITICAL 1개 >= 임계값 1" in msg
        assert "HIGH 6개 >= 임계값 5" in msg

    def test_no_vulnerabilities_passes_with_zero_counts(self, tmp_path):
        path = _write_result(tmp_path, {"vulnerabilities": []})
        passed, msg = check_gate(path, {"critical_threshold": 1, "high_threshold": 5})
        assert passed is True
        assert "총 취약점: 0개" in msg


class TestCIGateJsonVariations:
    """JSON 입력 형태 변형에 대한 회귀 보호."""

    def test_vulnerabilities_key_missing_passes(self, tmp_path):
        # 'vulnerabilities' 키가 없는 결과 파일도 안전하게 처리되어야 함
        path = _write_result(tmp_path, {"summary": {"total": 0}})
        passed, msg = check_gate(path, {"critical_threshold": 1, "high_threshold": 5})
        assert passed is True
        assert "총 취약점: 0개" in msg

    def test_unknown_severity_is_ignored(self, tmp_path):
        # 알 수 없는 severity 값(예: "INFO")은 카운트에 포함되지 않음
        path = _write_result(tmp_path, {"vulnerabilities": [
            {"severity": "INFO"},
            {"severity": "UNKNOWN"},
            {"severity": "HIGH"},
        ]})
        passed, msg = check_gate(path, {"critical_threshold": 1, "high_threshold": 5})
        assert passed is True
        assert "HIGH: 1" in msg

    def test_lowercase_severity_normalized(self, tmp_path):
        # severity가 소문자여도 대문자로 정규화되어 게이트가 동작해야 함
        path = _write_result(tmp_path, {"vulnerabilities": [
            {"severity": "critical"},
        ]})
        passed, _msg = check_gate(path, {"critical_threshold": 1, "high_threshold": 5})
        assert passed is False

    def test_missing_severity_field_treated_as_unknown(self, tmp_path):
        # severity 필드 자체가 없는 항목도 크래시 없이 처리
        path = _write_result(tmp_path, {"vulnerabilities": [
            {"rule_id": "B608"},  # severity 없음
            {"severity": "HIGH"},
        ]})
        passed, msg = check_gate(path, {"critical_threshold": 1, "high_threshold": 5})
        assert passed is True
        assert "총 취약점: 2개" in msg
        assert "HIGH: 1" in msg


class TestCIGateRiskLevelPrecedence:
    """risk_level 필드가 severity보다 우선한다는 규칙을 보호."""

    def test_risk_level_overrides_lower_severity(self, tmp_path):
        # severity=LOW지만 risk_level=critical → CRITICAL로 카운트
        path = _write_result(tmp_path, {"vulnerabilities": [
            {"severity": "LOW", "risk_level": "critical"},
        ]})
        passed, msg = check_gate(path, {"critical_threshold": 1, "high_threshold": 5})
        assert passed is False
        assert "CRITICAL 1개" in msg

    def test_risk_level_overrides_higher_severity(self, tmp_path):
        # severity=CRITICAL이지만 risk_level=low → LOW로 카운트, 통과해야 함
        path = _write_result(tmp_path, {"vulnerabilities": [
            {"severity": "CRITICAL", "risk_level": "low"},
        ]})
        passed, msg = check_gate(path, {"critical_threshold": 1, "high_threshold": 5})
        assert passed is True
        assert "LOW: 1" in msg
        assert "CRITICAL: 0" in msg

    def test_empty_risk_level_falls_back_to_severity(self, tmp_path):
        # risk_level이 빈 문자열이면 severity 사용
        path = _write_result(tmp_path, {"vulnerabilities": [
            {"severity": "CRITICAL", "risk_level": ""},
        ]})
        passed, _msg = check_gate(path, {"critical_threshold": 1, "high_threshold": 5})
        assert passed is False

    def test_risk_level_unknown_value_ignored(self, tmp_path):
        # risk_level이 알 수 없는 값이면 어떤 카운트에도 들어가지 않음
        path = _write_result(tmp_path, {"vulnerabilities": [
            {"severity": "HIGH", "risk_level": "informational"},
        ]})
        passed, msg = check_gate(path, {"critical_threshold": 1, "high_threshold": 5})
        assert passed is True
        # HIGH도 risk_level 우선 적용된 결과로 0
        assert "HIGH: 0" in msg


class TestCIGateConfigPrecedence:
    """설정 우선순위: 환경변수 > YAML 파일 > 기본값."""

    def test_yaml_config_overrides_defaults(self, tmp_path, monkeypatch):
        # 환경변수 비우고 YAML만 사용
        monkeypatch.delenv("DALLO_GATE_CRITICAL_THRESHOLD", raising=False)
        monkeypatch.delenv("DALLO_GATE_HIGH_THRESHOLD", raising=False)
        cfg_path = tmp_path / "gate.yml"
        cfg_path.write_text("critical_threshold: 99\nhigh_threshold: 42\n", encoding="utf-8")
        config = load_gate_config(str(cfg_path))
        assert config["critical_threshold"] == 99
        assert config["high_threshold"] == 42

    def test_env_overrides_yaml(self, tmp_path, monkeypatch):
        cfg_path = tmp_path / "gate.yml"
        cfg_path.write_text("critical_threshold: 5\nhigh_threshold: 10\n", encoding="utf-8")
        monkeypatch.setenv("DALLO_GATE_CRITICAL_THRESHOLD", "2")
        monkeypatch.setenv("DALLO_GATE_HIGH_THRESHOLD", "3")
        config = load_gate_config(str(cfg_path))
        assert config["critical_threshold"] == 2
        assert config["high_threshold"] == 3

    def test_invalid_env_value_falls_back(self, tmp_path, monkeypatch):
        # 정수가 아닌 환경변수는 기본값 유지
        monkeypatch.setenv("DALLO_GATE_CRITICAL_THRESHOLD", "not-a-number")
        monkeypatch.delenv("DALLO_GATE_HIGH_THRESHOLD", raising=False)
        config = load_gate_config(None)
        # 잘못된 값이면 기본 또는 YAML 값을 유지 (1이 기본)
        assert isinstance(config["critical_threshold"], int)

    def test_partial_yaml_keeps_defaults_for_missing_keys(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DALLO_GATE_CRITICAL_THRESHOLD", raising=False)
        monkeypatch.delenv("DALLO_GATE_HIGH_THRESHOLD", raising=False)
        cfg_path = tmp_path / "gate.yml"
        cfg_path.write_text("critical_threshold: 7\n", encoding="utf-8")
        config = load_gate_config(str(cfg_path))
        assert config["critical_threshold"] == 7
        # high_threshold는 기본값 5 유지
        assert config["high_threshold"] == 5

    def test_corrupt_yaml_does_not_crash(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DALLO_GATE_CRITICAL_THRESHOLD", raising=False)
        monkeypatch.delenv("DALLO_GATE_HIGH_THRESHOLD", raising=False)
        cfg_path = tmp_path / "gate.yml"
        cfg_path.write_text(":::not valid yaml:::\n", encoding="utf-8")
        config = load_gate_config(str(cfg_path))
        # 로드 실패 시 기본값으로 폴백되어야 함
        assert config["critical_threshold"] == 1
        assert config["high_threshold"] == 5


class TestCIGateThresholdBoundary:
    """임계값 경계 동작 (>=) 회귀 보호."""

    def test_exactly_at_critical_threshold_fails(self, tmp_path):
        # 정확히 임계값과 같으면 실패 (>= 비교)
        vulns = [{"severity": "CRITICAL"}, {"severity": "CRITICAL"}]
        path = _write_result(tmp_path, {"vulnerabilities": vulns})
        passed, _msg = check_gate(path, {"critical_threshold": 2, "high_threshold": 5})
        assert passed is False

    def test_one_below_high_threshold_passes(self, tmp_path):
        vulns = [{"severity": "HIGH"} for _ in range(4)]
        path = _write_result(tmp_path, {"vulnerabilities": vulns})
        passed, _msg = check_gate(path, {"critical_threshold": 1, "high_threshold": 5})
        assert passed is True
