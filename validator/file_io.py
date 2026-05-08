"""Validator 의 파일 쓰기 경계 어댑터 (validator/file_io.py).

Wave 4-O: ``TestRunner`` (sandbox 타깃 쓰기), ``SecurityChecker`` (보안
재검증 임시 fixed/original 쓰기), ``SyntaxChecker`` (flake8 임시 .py
쓰기) 가 직접 호출하던 ``open(..., 'w').write(...)`` /
``tempfile.NamedTemporaryFile(mode='w').write(...)`` 파일 I/O 책임을 작은
어댑터로 분리해, 테스트에서 실제 디스크 쓰기 없이 더블을 주입할 수 있도록
한다 (Clean Architecture: 외부 자원 어댑터, Wave 4-N ``analyzer/file_io.py``
와 동일 패턴).

설계 원칙:
  - ``write_text(path, content)``: UTF-8 텍스트로 ``open(path, "w").write``
    의 동작을 그대로 보존한다.
  - ``write_named_temp(content, suffix)``: ``tempfile.NamedTemporaryFile``
    의 ``mode="w"`` + ``suffix`` + ``delete=False`` 동작을 그대로 보존하면서
    UTF-8 명시 인코딩으로 묶고, 새로 만든 임시 파일의 절대 경로를 반환한다.
    호출자가 cleanup(``os.unlink``) 책임을 갖던 기존 동작을 그대로 유지한다.
  - 모듈 함수 ``get_default_file_io()`` 는 단일 기본 인스턴스를 lazy 로
    제공해, validator 모듈이 ``file_io=None`` 으로 생성되어도 일반 경로에서
    실제 파일 I/O 가 그대로 동작하도록 한다.
"""

from __future__ import annotations

import tempfile


class FileIO:
    """Validator 의 파일 쓰기 경계 어댑터."""

    def write_text(self, path: str, content: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def write_named_temp(self, content: str, suffix: str = "") -> str:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            f.flush()
            return f.name


_DEFAULT_FILE_IO = FileIO()


def get_default_file_io() -> FileIO:
    """프로세스 단위 기본 ``FileIO`` 인스턴스를 반환한다."""
    return _DEFAULT_FILE_IO


__all__ = ["FileIO", "get_default_file_io"]
