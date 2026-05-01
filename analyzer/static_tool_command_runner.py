"""정적 분석 도구 외부 명령 실행 어댑터 (analyzer/static_tool_command_runner.py).

Wave 3-G: ``BanditRunner`` / ``SemgrepRunner`` 가 직접 호출하던
``subprocess.run([...])`` 외부 도구 실행 책임을 infrastructure adapter 로
분리한다. 정적 분석 runner 들은 명령어 argv 구성, 출력 JSON 파싱, 한국어
에러 메시지 분기에 집중하고, 본 모듈은 외부 명령 실행 책임만 진다
(Clean Architecture: 외부 도구 어댑터).

설계 원칙:
  - argv 는 항상 ``list[str]`` (shell=False, ``shell=True`` 금지).
  - 결과는 ``CommandResult(stdout, stderr, returncode)`` 로 정규화 → 호출자가
    process API 디테일을 알지 않아도 된다.
  - 호출자는 ``BanditRunner(runner=...)`` / ``SemgrepRunner(runner=...)`` 로
    더블을 주입해 실제 도구 호출을 차단할 수 있다.
  - ``subprocess.TimeoutExpired`` / ``FileNotFoundError`` 는 그대로 전파해
    runner 의 기존 에러 메시지(한국어) 분기를 유지한다.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class CommandResult:
    """외부 명령 실행 결과 정규화 컨테이너."""

    stdout: str
    stderr: str
    returncode: int


class StaticToolCommandRunner:
    """list-argv 만 사용해 외부 명령을 실행하는 기본 runner.

    - ``shell=True`` 를 절대 사용하지 않는다.
    - 문자열 명령을 받지 않는다 (argv 는 반드시 list).
    """

    def run(
        self,
        argv: list[str],
        *,
        cwd: Optional[str] = None,
        timeout: int = 120,
    ) -> CommandResult:
        if not isinstance(argv, list) or not argv:
            raise ValueError("argv 는 비어있지 않은 list[str] 여야 합니다")

        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=timeout,
        )
        return CommandResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
        )


__all__ = ["CommandResult", "StaticToolCommandRunner"]
