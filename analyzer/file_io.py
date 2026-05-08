"""정적 분석 runner 의 파일 I/O 경계 어댑터 (analyzer/file_io.py).

Wave 4-N: ``BanditRunner`` / ``SemgrepRunner`` 가 직접 호출하던
``open(...).write`` / ``open(...).readlines`` 파일 I/O 책임을 작은
어댑터로 분리해, 테스트에서 실제 디스크 쓰기/읽기 없이 더블을 주입할 수
있도록 한다 (Clean Architecture: 외부 자원 어댑터).

설계 원칙:
  - ``write_json(path, payload)``: 부모 디렉토리 자동 생성, UTF-8 텍스트,
    ``indent=2`` + ``ensure_ascii=False`` 옵션을 그대로 보존한다 (현재
    ``json.dump(..., indent=2, ensure_ascii=False)`` 동작과 동일).
  - ``read_text_lines(path)``: Semgrep snippet enrichment 가 사용하는
    UTF-8 라인 단위 읽기. 예외 swallowing 은 호출자(SemgrepRunner) 수준에서
    유지되며, 본 어댑터는 표준 파일 예외를 그대로 전파한다.
  - 모듈 함수 ``get_default_file_io()`` 는 단일 기본 인스턴스를 lazy 로
    제공해, runner 가 ``file_io=None`` 으로 생성되어도 일반 경로에서
    실제 파일 I/O 가 그대로 동작하도록 한다.
"""

from __future__ import annotations

import json
import os
from typing import Any


class FileIO:
    """Bandit/Semgrep runner 의 파일 I/O 경계 어댑터."""

    def write_json(self, path: str, payload: Any) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

    def read_text_lines(self, path: str) -> list[str]:
        with open(path, "r", encoding="utf-8") as f:
            return f.readlines()


_DEFAULT_FILE_IO = FileIO()


def get_default_file_io() -> FileIO:
    """프로세스 단위 기본 ``FileIO`` 인스턴스를 반환한다."""
    return _DEFAULT_FILE_IO


__all__ = ["FileIO", "get_default_file_io"]
