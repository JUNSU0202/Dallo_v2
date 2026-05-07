"""
Bandit 정적 분석 실행 모듈

Bandit을 실행하고 결과를 정규화된 형태로 반환합니다.
SonarQube 결과와 통합할 수 있도록 공통 포맷을 사용합니다.
"""

import json
import subprocess
import os
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path

from shared.command_env import build_child_env
from analyzer.static_tool_command_runner import StaticToolCommandRunner


@dataclass
class Vulnerability:
    """정규화된 취약점 데이터 구조"""
    tool: str                          # 탐지 도구 (bandit, sonarqube)
    rule_id: str                       # 규칙 ID (예: B608)
    severity: str                      # HIGH, MEDIUM, LOW
    confidence: str                    # HIGH, MEDIUM, LOW
    title: str                         # 취약점 제목
    description: str                   # 설명
    file_path: str                     # 파일 경로
    line_number: int                   # 라인 번호
    col_offset: int = 0               # 컬럼 오프셋
    end_line: Optional[int] = None    # 끝 라인
    code_snippet: str = ""            # 취약점 코드 스니펫
    cwe_id: Optional[str] = None      # CWE ID
    owasp_category: Optional[str] = None  # OWASP 카테고리
    more_info: str = ""               # 참고 URL

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnalysisResult:
    """분석 결과 컨테이너"""
    tool: str
    target_path: str
    total_issues: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    raw_output: Optional[dict] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "target_path": self.target_path,
            "summary": {
                "total": self.total_issues,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "error": self.error,
        }


class BanditRunner:
    """Bandit 정적 분석 도구 실행기.

    외부 도구(``bandit``) 호출은 ``StaticToolCommandRunner`` 어댑터에
    위임한다. 테스트는 생성자에 더블을 주입해 실제 subprocess 호출을 막을
    수 있다 (Wave 3-G).
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        runner: Optional[StaticToolCommandRunner] = None,
    ):
        self.config_path = config_path or "config/bandit.yml"
        self._runner = runner or StaticToolCommandRunner()

    def run(self, target_path: str, output_path: Optional[str] = None) -> AnalysisResult:
        """
        Bandit 분석을 실행하고 결과를 반환합니다.

        Args:
            target_path: 분석할 디렉토리 또는 파일 경로
            output_path: JSON 리포트 저장 경로 (선택)

        Returns:
            AnalysisResult: 정규화된 분석 결과
        """
        result = AnalysisResult(tool="bandit", target_path=target_path)

        # Bandit 명령어 구성
        cmd = [
            "bandit",
            "-r", target_path,           # 재귀 분석
            "-f", "json",                # JSON 출력
            "-q",                        # progress bar 억제 (stdout JSON 오염 방지)
            "--confidence-level", "all", # 모든 신뢰도
            "--severity-level", "all",   # 모든 심각도
        ]

        # 설정 파일이 존재하면 적용
        if os.path.exists(self.config_path):
            cmd.extend(["-c", self.config_path])

        try:
            # Bandit은 취약점 발견 시 exit code 1을 반환하므로
            # check=False로 실행 (어댑터는 returncode 를 그대로 반환)
            # Wave 4-F: 부모 환경 전체를 자식에게 상속시키지 않고
            # ``build_child_env`` 의 보수적 allowlist + 시크릿 이름 deny filter
            # 를 거친 sanitized env 만 전달한다. ``ANTHROPIC_API_KEY`` /
            # ``GITHUB_TOKEN`` / ``AWS_SECRET_ACCESS_KEY`` 등 ambient 시크릿이
            # bandit child 에 상속되어 로그/덤프로 누출되는 위험을 차단.
            proc = self._runner.run(cmd, timeout=120, env=build_child_env())

            # JSON 파싱
            if proc.stdout:
                raw = self._parse_json_output(proc.stdout)
                result.raw_output = raw

                # 리포트 저장
                if output_path:
                    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
                    with open(output_path, "w", encoding="utf-8") as f:
                        json.dump(raw, f, indent=2, ensure_ascii=False)

                # 결과 파싱
                result = self._parse_results(raw, result)
            elif proc.stderr:
                result.error = proc.stderr.strip()

        except subprocess.TimeoutExpired:
            result.error = "Bandit 분석 시간 초과 (120초)"
        except json.JSONDecodeError as e:
            result.error = f"Bandit 출력 JSON 파싱 실패: {e}"
        except FileNotFoundError:
            result.error = "Bandit이 설치되어 있지 않습니다. pip install bandit"

        return result

    @staticmethod
    def _parse_json_output(stdout: str) -> dict:
        """Bandit stdout에서 JSON을 파싱합니다.

        -q 플래그로 progress bar를 억제하지만, 이전 버전이나
        예상치 못한 환경에서 stdout 앞에 비-JSON 텍스트가 섞일 수 있으므로
        직접 파싱 실패 시 '{' 위치를 찾아 재시도합니다.
        """
        # 1차: 직접 파싱
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            pass

        # 2차: JSON 시작점('{')을 찾아 재파싱 (progress bar 등 접두사 제거)
        json_start = stdout.find("{")
        if json_start > 0:
            return json.loads(stdout[json_start:])

        # 둘 다 실패하면 원래 에러를 발생시킴
        raise json.JSONDecodeError("Bandit stdout에서 JSON을 찾을 수 없습니다", stdout, 0)

    def _parse_results(self, raw: dict, result: AnalysisResult) -> AnalysisResult:
        """Bandit JSON 출력을 정규화된 형태로 변환"""

        results_list = raw.get("results", [])
        metrics = raw.get("metrics", {}).get("_totals", {})

        result.total_issues = len(results_list)
        result.high_count = metrics.get("SEVERITY.HIGH", 0)
        result.medium_count = metrics.get("SEVERITY.MEDIUM", 0)
        result.low_count = metrics.get("SEVERITY.LOW", 0)

        for item in results_list:
            vuln = Vulnerability(
                tool="bandit",
                rule_id=item.get("test_id", ""),
                severity=item.get("issue_severity", "UNDEFINED"),
                confidence=item.get("issue_confidence", "UNDEFINED"),
                title=item.get("test_name", ""),
                description=item.get("issue_text", ""),
                file_path=item.get("filename", ""),
                line_number=item.get("line_number", 0),
                col_offset=item.get("col_offset", 0),
                end_line=item.get("end_col_offset"),
                code_snippet=item.get("code", ""),
                cwe_id=self._get_cwe(item),
                more_info=item.get("more_info", ""),
            )
            result.vulnerabilities.append(vuln)

        return result

    def _get_cwe(self, item: dict) -> Optional[str]:
        """CWE ID 추출"""
        cwe = item.get("issue_cwe", {})
        if isinstance(cwe, dict) and cwe.get("id"):
            return f"CWE-{cwe['id']}"
        return None

    def run_single_file(self, file_path: str) -> AnalysisResult:
        """단일 파일에 대해 Bandit 분석 실행"""
        return self.run(file_path)


def run_bandit_analysis(
    target_path: str,
    config_path: Optional[str] = None,
    output_path: Optional[str] = None,
) -> AnalysisResult:
    """편의 함수: Bandit 분석 실행"""
    runner = BanditRunner(config_path=config_path)
    output = output_path or "reports/bandit_report.json"
    return runner.run(target_path, output_path=output)


# CLI에서 직접 실행 가능
if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "test_targets/"
    print(f"[*] Bandit 분석 시작: {target}")

    result = run_bandit_analysis(target)

    if result.error:
        print(f"[!] 오류: {result.error}")
    else:
        print(f"[+] 분석 완료: 총 {result.total_issues}건 탐지")
        print(f"    HIGH: {result.high_count}, MEDIUM: {result.medium_count}, LOW: {result.low_count}")
        print()
        for v in result.vulnerabilities:
            print(f"  [{v.severity}] {v.rule_id} - {v.title}")
            print(f"    파일: {v.file_path}:{v.line_number}")
            print(f"    설명: {v.description}")
            print()
