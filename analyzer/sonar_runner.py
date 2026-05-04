"""
SonarQube 정적 분석 실행 모듈

SonarQube API를 통해 코드 분석을 실행하고 결과를 조회합니다.
Docker 환경에서 SonarQube가 실행 중이어야 합니다.

사전 준비:
  1. docker-compose up -d (docker/ 디렉토리)
  2. http://localhost:9000 에서 프로젝트 생성 및 토큰 발급
  3. sonar-scanner 설치 또는 Docker로 실행
"""

import os
import time
from typing import Callable, Optional
from dataclasses import dataclass

from analyzer.bandit_runner import Vulnerability, AnalysisResult
from analyzer.sonar_http_client import (
    HttpConnectionError,
    HttpRequestError,
    SonarHttpClient,
)
from analyzer.static_tool_command_runner import StaticToolCommandRunner


@dataclass
class SonarConfig:
    """SonarQube 연결 설정"""
    host_url: str = "http://localhost:9000"
    token: str = ""
    project_key: str = "dallo-devsecops"


class SonarRunner:
    """SonarQube 분석 실행 및 결과 조회.

    ``sonar-scanner`` subprocess 호출은 ``StaticToolCommandRunner`` 어댑터에
    위임한다(Wave 3-H). REST API HTTP 호출은 ``SonarHttpClient`` 어댑터에
    위임한다(Wave 3-I). ``wait_for_analysis()`` 의 polling clock/sleeper 도
    생성자 주입형 seam 으로 분리되어 있다(Wave 3-J). 테스트는 생성자에 더블
    (``scanner_runner`` / ``http_client`` / ``clock`` / ``sleeper``)을 주입해
    실제 subprocess 호출이나 네트워크 I/O, 실제 sleep 을 막을 수 있다. 본
    모듈은 argv 구성, URL 구성, 응답 파싱, 한국어 에러 메시지 분기에만
    집중한다.
    """

    def __init__(
        self,
        config: Optional[SonarConfig] = None,
        scanner_runner: Optional[StaticToolCommandRunner] = None,
        http_client: Optional[SonarHttpClient] = None,
        clock: Optional[Callable[[], float]] = None,
        sleeper: Optional[Callable[[float], None]] = None,
    ):
        self.config = config or SonarConfig(
            token=os.environ.get("SONAR_TOKEN", ""),
        )
        self.base_url = self.config.host_url
        self.auth = (self.config.token, "")
        self._scanner_runner = scanner_runner or StaticToolCommandRunner()
        self._http_client = http_client or SonarHttpClient()
        self._clock = clock or time.time
        self._sleeper = sleeper or time.sleep

    def is_available(self) -> bool:
        """SonarQube 서버가 실행 중인지 확인"""
        try:
            resp = self._http_client.get(
                f"{self.base_url}/api/system/status",
                timeout=5,
            )
            return resp.status_code == 200 and resp.json().get("status") == "UP"
        except HttpConnectionError:
            return False

    def run_scan(self, project_path: str = ".") -> bool:
        """
        sonar-scanner를 실행하여 코드를 분석합니다.

        사전 조건: sonar-scanner가 PATH에 있거나 Docker로 실행

        Wave 4-D: Sonar 토큰은 더 이상 argv (``-Dsonar.token=...``) 로
        넘기지 않고, 비어있지 않은 경우에만 ``SONAR_TOKEN`` 환경변수로
        child process 에 주입한다. argv 노출(프로세스 목록/로그)을 막기
        위함이며, 토큰이 비어있으면 환경 변수도 주입하지 않아 빈 값이
        실수로 인증 경로에 쓰이지 않게 한다.
        """
        cmd = [
            "sonar-scanner",
            f"-Dsonar.projectKey={self.config.project_key}",
            f"-Dsonar.host.url={self.base_url}",
            f"-Dsonar.projectBaseDir={project_path}",
        ]

        scanner_env: Optional[dict] = None
        if self.config.token:
            scanner_env = os.environ.copy()
            scanner_env["SONAR_TOKEN"] = self.config.token

        # sonar-project.properties 파일이 있으면 자동으로 읽음
        try:
            proc = self._scanner_runner.run(cmd, timeout=300, env=scanner_env)
            return proc.returncode == 0
        except FileNotFoundError:
            print("[!] sonar-scanner가 설치되어 있지 않습니다.")
            print("    설치 방법: https://docs.sonarqube.org/latest/analyzing-source-code/scanners/sonarscanner/")
            return False

    def get_issues(
        self,
        severity: Optional[str] = None,
        page_size: int = 100,
    ) -> AnalysisResult:
        """
        SonarQube API에서 이슈(취약점) 목록을 조회합니다.

        Args:
            severity: 필터할 심각도 (BLOCKER, CRITICAL, MAJOR, MINOR, INFO)
            page_size: 페이지당 결과 수
        """
        result = AnalysisResult(tool="sonarqube", target_path=self.config.project_key)

        params = {
            "componentKeys": self.config.project_key,
            "ps": page_size,
            "types": "VULNERABILITY,BUG,CODE_SMELL",
        }
        if severity:
            params["severities"] = severity

        try:
            resp = self._http_client.get(
                f"{self.base_url}/api/issues/search",
                params=params,
                auth=self.auth,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except HttpRequestError as e:
            result.error = str(e)
            return result

        result.raw_output = data

        # SonarQube 심각도 → 프로젝트 심각도 매핑
        severity_map = {
            "BLOCKER": "HIGH",
            "CRITICAL": "HIGH",
            "MAJOR": "MEDIUM",
            "MINOR": "LOW",
            "INFO": "LOW",
        }

        for issue in data.get("issues", []):
            sonar_severity = issue.get("severity", "INFO")
            mapped_severity = severity_map.get(sonar_severity, "LOW")

            # 파일 경로에서 프로젝트 키 제거
            component = issue.get("component", "")
            file_path = component.split(":", 1)[-1] if ":" in component else component

            vuln = Vulnerability(
                tool="sonarqube",
                rule_id=issue.get("rule", ""),
                severity=mapped_severity,
                confidence="HIGH",  # SonarQube는 confidence 개념 없음
                title=issue.get("message", ""),
                description=issue.get("message", ""),
                file_path=file_path,
                line_number=issue.get("line", 0),
            )
            result.vulnerabilities.append(vuln)

            # 카운트
            if mapped_severity == "HIGH":
                result.high_count += 1
            elif mapped_severity == "MEDIUM":
                result.medium_count += 1
            else:
                result.low_count += 1

        result.total_issues = len(result.vulnerabilities)
        return result

    def wait_for_analysis(self, timeout: int = 120) -> bool:
        """분석 완료를 대기합니다."""
        start = self._clock()
        while self._clock() - start < timeout:
            try:
                resp = self._http_client.get(
                    f"{self.base_url}/api/ce/activity",
                    params={
                        "component": self.config.project_key,
                        "ps": 1,
                        "onlyCurrents": "true",
                    },
                    auth=self.auth,
                    timeout=10,
                )
                tasks = resp.json().get("tasks", [])
                if tasks and tasks[0].get("status") == "SUCCESS":
                    return True
            except HttpRequestError:
                pass
            self._sleeper(5)
        return False
