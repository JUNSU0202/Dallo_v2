"""
의존성 취약점 분석 모듈 (analyzer/dependency_scanner.py)

프로젝트의 라이브러리 의존성을 스캔하여 알려진 CVE를 탐지합니다.
SBOM(Software Bill of Materials) 개념을 적용합니다.

지원 도구:
  - pip-audit: Python (requirements.txt, Pipfile, setup.py)
  - npm audit: JavaScript/TypeScript (package.json)
  - (확장 가능: cargo audit, go mod 등)

사용법:
    from analyzer.dependency_scanner import DependencyScanner

    scanner = DependencyScanner()
    result = scanner.scan("/path/to/project")
    # 또는 requirements.txt 내용을 직접 전달
    result = scanner.scan_requirements_text("flask==2.0.0\\nrequests==2.25.0")
"""

import json
import subprocess
import os
import tempfile
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional

from shared.command_env import build_child_env
from analyzer.dependency_command_runner import DependencyCommandRunner
from analyzer.file_io import FileIO, get_default_file_io

logger = logging.getLogger(__name__)


# Wave 4-H: pip-audit 전용 child env allowlist.
# build_child_env 의 기본 allowlist (PATH/HOME/LANG/proxy 등) 외에, pip 가
# 정상 동작하기 위해 필요한 비-시크릿 운영 변수만 추가한다. 사설 PyPI
# 레지스트리/자격증명 관련 변수 (PIP_INDEX_URL / PIP_EXTRA_INDEX_URL /
# PIP_TRUSTED_HOST / PIP_CONFIG_FILE 등) 는 의도적으로 ambient 상속을
# 허용하지 않는다 — 향후 사설 레지스트리 기능이 필요해지면 별도 wave 에서
# 명시적 capability extras 패턴으로 도입.
_PIP_AUDIT_ENV_ALLOWLIST: tuple[str, ...] = (
    "PIP_CACHE_DIR",
    "PIP_DISABLE_PIP_VERSION_CHECK",
    "PIP_NO_INPUT",
    "PIP_CERT",
    "PIP_CLIENT_CERT",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "XDG_CACHE_HOME",
)


# Wave 4-H: npm 전용 child env allowlist.
# 사설 npm 레지스트리/자격증명 관련 변수 (NPM_CONFIG_REGISTRY /
# NPM_CONFIG_USERCONFIG / NPM_CONFIG_HTTPS_PROXY / NPM_CONFIG_PROXY /
# 소문자 ``npm_config_*`` / npm ``_authToken`` 등) 는 의도적으로 ambient
# 상속을 허용하지 않는다.
_NPM_ENV_ALLOWLIST: tuple[str, ...] = (
    "NPM_CONFIG_CACHE",
    "NPM_CONFIG_AUDIT_LEVEL",
    "NPM_CONFIG_STRICT_SSL",
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "XDG_CACHE_HOME",
)


@dataclass
class DependencyVulnerability:
    """의존성 취약점 정보"""
    package: str                       # 패키지명
    installed_version: str             # 설치 버전
    fixed_version: str = ""            # 수정된 버전
    vulnerability_id: str = ""         # CVE ID 또는 PYSEC/GHSA ID
    description: str = ""              # 취약점 설명
    severity: str = "UNKNOWN"          # HIGH/MEDIUM/LOW/CRITICAL
    url: str = ""                      # 참고 URL

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DependencyScanResult:
    """의존성 스캔 결과"""
    tool: str                          # pip-audit / npm-audit
    project_path: str = ""
    total_packages: int = 0            # 전체 패키지 수
    total_vulnerabilities: int = 0     # 취약점 수
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    vulnerabilities: list[DependencyVulnerability] = field(default_factory=list)
    packages: list[dict] = field(default_factory=list)  # 전체 패키지 목록 (SBOM)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "project_path": self.project_path,
            "summary": {
                "total_packages": self.total_packages,
                "total_vulnerabilities": self.total_vulnerabilities,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "packages": self.packages,
            "error": self.error,
        }


class DependencyScanner:
    """프로젝트 의존성 취약점 스캐너.

    외부 도구(pip-audit / npm) 호출은 ``DependencyCommandRunner`` 어댑터에
    위임한다. 테스트는 생성자에 더블을 주입해 실제 subprocess 호출을 막을
    수 있다 (Wave 3-F).
    """

    def __init__(
        self,
        runner: Optional[DependencyCommandRunner] = None,
        *,
        file_io: Optional[FileIO] = None,
    ):
        self._runner = runner or DependencyCommandRunner()
        # Wave 4-Z: requirements/package.json 임시 쓰기 및 fallback 라인 읽기
        # 경계를 keyword-only seam 으로 분리. ``None`` 이면 사용 시점에 lazy
        # 로 ``get_default_file_io()`` 를 해석한다 — 운영 동작 무변경.
        self._file_io = file_io

    def _io(self) -> FileIO:
        return self._file_io or get_default_file_io()

    def scan(self, project_path: str) -> list[DependencyScanResult]:
        """
        프로젝트 디렉토리를 스캔하여 의존성 취약점을 탐지합니다.
        requirements.txt, package.json 등을 자동 감지합니다.

        Args:
            project_path: 프로젝트 디렉토리 경로

        Returns:
            도구별 스캔 결과 리스트
        """
        results = []

        if os.path.isfile(project_path):
            project_path = os.path.dirname(project_path)

        # Python: requirements.txt 감지
        req_path = os.path.join(project_path, "requirements.txt")
        if os.path.exists(req_path):
            results.append(self._scan_pip(req_path))

        # JavaScript: package.json 감지
        pkg_path = os.path.join(project_path, "package.json")
        if os.path.exists(pkg_path):
            results.append(self._scan_npm(project_path))

        # package-lock.json만 있는 경우
        lock_path = os.path.join(project_path, "package-lock.json")
        if not os.path.exists(pkg_path) and os.path.exists(lock_path):
            results.append(self._scan_npm(project_path))

        if not results:
            results.append(DependencyScanResult(
                tool="none",
                project_path=project_path,
                error="의존성 파일을 찾을 수 없습니다 (requirements.txt, package.json)",
            ))

        return results

    def scan_requirements_text(self, requirements_text: str) -> DependencyScanResult:
        """
        requirements.txt 내용을 직접 전달받아 스캔합니다.
        (대시보드에서 텍스트 입력으로 스캔할 때 사용)
        """
        tmp_dir = tempfile.mkdtemp(prefix="dallo_deps_")
        try:
            req_path = os.path.join(tmp_dir, "requirements.txt")
            self._io().write_text(req_path, requirements_text)
            return self._scan_pip(req_path)
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def scan_package_json_text(self, package_json_text: str) -> DependencyScanResult:
        """package.json 내용을 직접 전달받아 스캔합니다."""
        tmp_dir = tempfile.mkdtemp(prefix="dallo_deps_")
        try:
            pkg_path = os.path.join(tmp_dir, "package.json")
            self._io().write_text(pkg_path, package_json_text)
            # npm install 실행 (외부 명령 호출은 어댑터 경유)
            # Wave 4-H: 부모 env 전체를 자식에게 상속시키지 않고
            # ``build_child_env`` 의 보수적 allowlist + 시크릿 이름 deny
            # filter 를 거친 sanitized env 만 전달한다. ``NPM_TOKEN`` /
            # ``NPM_CONFIG_REGISTRY`` / ``NPM_CONFIG_USERCONFIG`` 등 사설
            # 레지스트리/자격증명 변수가 npm 자식 프로세스로 누출되는 위험
            # 을 차단.
            self._runner.run(
                ["npm", "install", "--package-lock-only"],
                cwd=tmp_dir,
                timeout=60,
                env=build_child_env(allowlist=_NPM_ENV_ALLOWLIST),
            )
            return self._scan_npm(tmp_dir)
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _scan_pip(self, requirements_path: str) -> DependencyScanResult:
        """pip-audit으로 Python 의존성 스캔"""
        result = DependencyScanResult(
            tool="pip-audit",
            project_path=requirements_path,
        )

        try:
            # pip-audit JSON 출력
            cmd = [
                "pip-audit",
                "-r", requirements_path,
                "--format", "json",
                "--output", "-",
            ]

            # Wave 4-H: 부모 env 전체를 자식에게 상속시키지 않고
            # ``build_child_env`` 의 보수적 allowlist + 시크릿 이름 deny
            # filter 를 거친 sanitized env 만 전달한다. ``PYPI_TOKEN`` /
            # ``PIP_INDEX_URL`` / ``PIP_EXTRA_INDEX_URL`` / ``PIP_CONFIG_FILE``
            # 등 사설 레지스트리/자격증명 변수가 pip-audit 자식 프로세스로
            # 누출되는 위험을 차단.
            proc = self._runner.run(
                cmd,
                timeout=120,
                env=build_child_env(allowlist=_PIP_AUDIT_ENV_ALLOWLIST),
            )

            output = proc.stdout
            if not output:
                # pip-audit이 설치되지 않았거나 오류
                if "No module named" in (proc.stderr or "") or proc.returncode == 127:
                    result.error = "pip-audit이 설치되어 있지 않습니다. pip install pip-audit"
                    return self._fallback_pip_scan(requirements_path, result)
                result.error = proc.stderr.strip()[:500] if proc.stderr else "pip-audit 실행 실패"
                return self._fallback_pip_scan(requirements_path, result)

            raw = json.loads(output)
            result = self._parse_pip_audit(raw, result)

        except subprocess.TimeoutExpired:
            result.error = "pip-audit 시간 초과 (120초)"
        except json.JSONDecodeError:
            result.error = "pip-audit 출력 파싱 실패"
            return self._fallback_pip_scan(requirements_path, result)
        except FileNotFoundError:
            result.error = "pip-audit 미설치"
            return self._fallback_pip_scan(requirements_path, result)

        return result

    def _parse_pip_audit(self, raw: dict, result: DependencyScanResult) -> DependencyScanResult:
        """pip-audit JSON 결과 파싱"""
        dependencies = raw.get("dependencies", [])
        result.total_packages = len(dependencies)

        for dep in dependencies:
            pkg_name = dep.get("name", "")
            version = dep.get("version", "")

            result.packages.append({
                "name": pkg_name,
                "version": version,
            })

            for vuln in dep.get("vulns", []):
                severity = self._normalize_severity(vuln.get("fix_versions", []))
                dv = DependencyVulnerability(
                    package=pkg_name,
                    installed_version=version,
                    fixed_version=", ".join(vuln.get("fix_versions", [])),
                    vulnerability_id=vuln.get("id", ""),
                    description=vuln.get("description", "")[:500],
                    severity=severity,
                    url=f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
                )
                result.vulnerabilities.append(dv)

                if severity == "CRITICAL":
                    result.critical_count += 1
                elif severity == "HIGH":
                    result.high_count += 1
                elif severity == "MEDIUM":
                    result.medium_count += 1
                else:
                    result.low_count += 1

        result.total_vulnerabilities = len(result.vulnerabilities)
        return result

    def _fallback_pip_scan(self, requirements_path: str, result: DependencyScanResult) -> DependencyScanResult:
        """pip-audit 미설치 시 requirements.txt 파싱으로 기본 정보 제공"""
        try:
            lines = self._io().read_text_lines(requirements_path)

            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # flask==2.0.0 또는 flask>=2.0
                parts = line.split("==")
                if len(parts) == 2:
                    result.packages.append({"name": parts[0].strip(), "version": parts[1].strip()})
                else:
                    parts = line.split(">=")
                    name = parts[0].strip()
                    ver = parts[1].strip() if len(parts) == 2 else "unknown"
                    result.packages.append({"name": name, "version": ver})

            result.total_packages = len(result.packages)
            if not result.error:
                result.error = "pip-audit 미설치 — 패키지 목록만 표시 (취약점 스캔 불가)"
        except Exception as e:
            result.error = f"requirements.txt 파싱 실패: {e}"

        return result

    def _scan_npm(self, project_path: str) -> DependencyScanResult:
        """npm audit으로 JavaScript 의존성 스캔"""
        result = DependencyScanResult(
            tool="npm-audit",
            project_path=project_path,
        )

        try:
            cmd = ["npm", "audit", "--json"]
            # Wave 4-H: 부모 env 전체를 자식에게 상속시키지 않고
            # ``build_child_env`` 의 보수적 allowlist + 시크릿 이름 deny
            # filter 를 거친 sanitized env 만 전달한다.
            proc = self._runner.run(
                cmd,
                cwd=project_path,
                timeout=120,
                env=build_child_env(allowlist=_NPM_ENV_ALLOWLIST),
            )

            output = proc.stdout
            if not output:
                result.error = proc.stderr.strip()[:500] if proc.stderr else "npm audit 실행 실패"
                return result

            raw = json.loads(output)
            result = self._parse_npm_audit(raw, result)

        except subprocess.TimeoutExpired:
            result.error = "npm audit 시간 초과 (120초)"
        except json.JSONDecodeError:
            result.error = "npm audit 출력 파싱 실패"
        except FileNotFoundError:
            result.error = "npm이 설치되어 있지 않습니다"

        return result

    def _parse_npm_audit(self, raw: dict, result: DependencyScanResult) -> DependencyScanResult:
        """npm audit JSON 결과 파싱"""
        # npm audit v2 format
        vulns = raw.get("vulnerabilities", {})

        for pkg_name, info in vulns.items():
            severity = (info.get("severity", "low") or "low").upper()
            if severity == "MODERATE":
                severity = "MEDIUM"

            for via in info.get("via", []):
                if isinstance(via, dict):
                    dv = DependencyVulnerability(
                        package=pkg_name,
                        installed_version=info.get("range", ""),
                        vulnerability_id=via.get("source", str(via.get("url", ""))),
                        description=via.get("title", "")[:500],
                        severity=severity,
                        url=via.get("url", ""),
                    )
                    result.vulnerabilities.append(dv)

            if severity == "CRITICAL":
                result.critical_count += 1
            elif severity == "HIGH":
                result.high_count += 1
            elif severity == "MEDIUM":
                result.medium_count += 1
            else:
                result.low_count += 1

        # 메타데이터
        metadata = raw.get("metadata", {})
        result.total_packages = metadata.get("totalDependencies", 0)
        result.total_vulnerabilities = len(result.vulnerabilities)

        return result

    @staticmethod
    def _normalize_severity(fix_versions: list) -> str:
        """수정 버전 존재 여부로 대략적 심각도 판단 (pip-audit은 severity를 직접 제공하지 않음)"""
        if fix_versions:
            return "HIGH"
        return "MEDIUM"
