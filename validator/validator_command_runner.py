"""검증기 외부 명령 실행 어댑터 (validator/validator_command_runner.py).

Wave 4-A: ``SyntaxChecker.check_with_flake8()`` 와 ``TestRunner._run_in_sandbox()``
가 직접 호출하던 ``subprocess.run([...])`` 외부 도구 실행 책임을
infrastructure adapter 로 분리한다. 검증기(domain/service) 는 임시 디렉토리
관리, ``PatchSuggestion`` 결과 매핑, 한국어 에러 분기에 집중하고, 본 모듈은
외부 명령 실행 책임만 진다 (Clean Architecture: 외부 도구 어댑터).

설계 원칙:
  - argv 는 항상 ``list[str]`` (shell=False, ``shell=True`` 금지).
  - 결과는 ``CommandResult(stdout, stderr, returncode)`` 로 정규화된다.
  - 호출자는 생성자에 더블을 주입해 실제 도구 호출을 차단할 수 있다
    (``SyntaxChecker(runner=...)`` / ``TestRunner(runner=...)``).
  - ``subprocess.TimeoutExpired`` / ``FileNotFoundError`` 는 그대로 전파해
    호출자의 기존 에러 메시지(한국어) 분기를 유지한다.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Mapping, Optional, Union


@dataclass(frozen=True)
class CommandResult:
    """외부 명령 실행 결과 정규화 컨테이너."""

    stdout: str
    stderr: str
    returncode: int


class ValidatorCommandRunner:
    """list-argv 만 사용해 외부 명령을 실행하는 기본 runner.

    - ``shell=True`` 를 절대 사용하지 않는다.
    - 문자열 명령을 받지 않는다 (argv 는 반드시 list).
    - ``env`` 가 주어지면 child process 의 환경변수로 그대로 전달한다
      (None 이면 부모 프로세스 환경 상속). Wave 4-I 에서 flake8 /
      sandbox pytest 자식 프로세스에 ``build_child_env(...)`` 로 sanitized
      env 만 넘기기 위한 seam.
    """

    def run(
        self,
        argv: list[str],
        *,
        cwd: Optional[str] = None,
        timeout: Optional[Union[int, float]] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> CommandResult:
        if not isinstance(argv, list) or not argv:
            raise ValueError("argv 는 비어있지 않은 list[str] 여야 합니다")

        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=timeout,
            env=env,
        )
        return CommandResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
        )


__all__ = ["CommandResult", "ValidatorCommandRunner"]
