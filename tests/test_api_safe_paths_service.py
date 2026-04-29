"""safe_paths 헬퍼 단위 테스트 (tests/test_api_safe_paths_service.py).

Wave 3-B: 라우터/서비스에 흩어져 있던 파일명 sanitize 로직을
``api.services.safe_paths`` 한 곳으로 모은 뒤 동작과 회귀 케이스를
보증한다. 모듈은 FastAPI / api.server 를 import 하지 않아야 한다.
"""

from __future__ import annotations

import os


# ============================================================
# Import surface
# ============================================================


class TestSafePathsImportSurface:
    def test_module_does_not_import_api_server(self):
        import ast
        import inspect

        from api.services import safe_paths as svc

        tree = ast.parse(inspect.getsource(svc))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name != "api.server", "api.server 직접 import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "api.server", "from api.server import 금지"

    def test_module_does_not_import_fastapi(self):
        import ast
        import inspect

        from api.services import safe_paths as svc

        src = inspect.getsource(svc)
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert not n.name.startswith("fastapi"), (
                        "safe_paths 는 fastapi import 금지"
                    )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert not module.startswith("fastapi"), (
                    "safe_paths 는 fastapi import 금지"
                )


# ============================================================
# sanitize_filename — 슬래시/백슬래시/트래버설/유니코드/빈 입력
# ============================================================


class TestSanitizeFilename:
    def test_plain_filename_unchanged(self):
        from api.services.safe_paths import sanitize_filename

        assert sanitize_filename("report.html") == "report.html"

    def test_forward_slash_replaced(self):
        from api.services.safe_paths import sanitize_filename

        assert sanitize_filename("a/b.html") == "a_b.html"

    def test_backslash_replaced(self):
        from api.services.safe_paths import sanitize_filename

        assert sanitize_filename("a\\b.html") == "a_b.html"

    def test_nested_path_flattened(self):
        from api.services.safe_paths import sanitize_filename

        assert sanitize_filename("src/sub/dir/evil.py") == "src_sub_dir_evil.py"

    def test_traversal_segment_replaced(self):
        """``../secret.html`` → ``.._secret.html`` (현재 inline 동작 보존)."""
        from api.services.safe_paths import sanitize_filename

        assert sanitize_filename("../secret.html") == ".._secret.html"

    def test_repeated_traversal_segments_replaced(self):
        from api.services.safe_paths import sanitize_filename

        assert sanitize_filename("../../etc/passwd") == ".._.._etc_passwd"

    def test_mixed_separators_replaced(self):
        from api.services.safe_paths import sanitize_filename

        # 윈도/유닉스 혼합 — 모두 _ 로 평탄화
        assert sanitize_filename("a\\b/c.txt") == "a_b_c.txt"

    def test_unicode_filename_passthrough(self):
        from api.services.safe_paths import sanitize_filename

        # 한글 같은 유니코드 문자는 그대로 보존되어야 한다
        assert sanitize_filename("리포트.html") == "리포트.html"

    def test_empty_string_falls_back_to_default(self):
        from api.services.safe_paths import sanitize_filename

        assert sanitize_filename("") == "report"

    def test_empty_string_with_custom_default(self):
        from api.services.safe_paths import sanitize_filename

        assert sanitize_filename("", default="anon.bin") == "anon.bin"

    def test_does_not_produce_absolute_path_with_separator_input(self):
        """``/etc/passwd`` 같은 절대 경로 입력도 sanitize 후에는
        os.path.isabs() 로 절대 경로가 되지 않아야 한다."""
        from api.services.safe_paths import sanitize_filename

        sanitized = sanitize_filename("/etc/passwd")
        assert not os.path.isabs(sanitized)
        assert sanitized == "_etc_passwd"


# ============================================================
# report_download_basename — URL 노출용 basename
# ============================================================


class TestReportDownloadBasename:
    def test_basename_extracted_from_absolute_path(self):
        from api.services.safe_paths import report_download_basename

        # 플랫폼 분리자 차이를 피하기 위해 os.path.join 으로 구성
        path = os.path.join(os.sep, "var", "tmp", "report.html")
        assert report_download_basename(path) == "report.html"

    def test_basename_passthrough_for_simple_name(self):
        from api.services.safe_paths import report_download_basename

        assert report_download_basename("report.md") == "report.md"

    def test_basename_strips_relative_dir_prefix(self):
        from api.services.safe_paths import report_download_basename

        path = os.path.join("reports", "out.html")
        assert report_download_basename(path) == "out.html"


# ============================================================
# 트래버설 회귀 — sanitize 후 REPORTS_DIR 밖을 가리키지 않는다
# ============================================================


class TestSanitizeStaysUnderRoot:
    """sanitize 결과를 ``base`` 에 단순 join 한 결과가 ``base`` 트리를 벗어나지 않는다."""

    def test_traversal_resolves_back_inside_base(self, tmp_path):
        from api.services.safe_paths import sanitize_filename

        base = str(tmp_path)
        candidate = sanitize_filename("../../etc/passwd")
        joined = os.path.realpath(os.path.join(base, candidate))
        # base 의 자식 노드 (또는 base 자체) 안에 머물러야 한다
        assert joined.startswith(os.path.realpath(base) + os.sep), joined

    def test_backslash_traversal_stays_inside_base(self, tmp_path):
        from api.services.safe_paths import sanitize_filename

        base = str(tmp_path)
        candidate = sanitize_filename("..\\..\\windows\\system32")
        joined = os.path.realpath(os.path.join(base, candidate))
        assert joined.startswith(os.path.realpath(base) + os.sep), joined

    def test_absolute_input_stays_inside_base(self, tmp_path):
        from api.services.safe_paths import sanitize_filename

        base = str(tmp_path)
        candidate = sanitize_filename("/etc/shadow")
        # leading '/' 가 '_' 로 치환되므로 절대 경로가 아님
        assert not os.path.isabs(candidate)
        joined = os.path.realpath(os.path.join(base, candidate))
        assert joined.startswith(os.path.realpath(base) + os.sep), joined


# ============================================================
# 라우터/서비스가 동일 헬퍼를 공유하는지 회귀 확인
# ============================================================


class TestCallSitesShareHelper:
    """``api.routers.report._safe_report_filename`` 와
    ``api.services.patch_application.sanitize_filename`` 이 모두
    safe_paths 헬퍼와 동일한 결과를 내야 한다.
    """

    def test_report_router_helper_matches_safe_paths(self):
        from api.routers.report import _safe_report_filename
        from api.services.safe_paths import sanitize_filename

        for raw in ("a/b.html", "a\\b.html", "../secret.html", "ok.html"):
            assert _safe_report_filename(raw) == sanitize_filename(raw)

    def test_patch_service_helper_matches_safe_paths(self):
        from api.services.patch_application import sanitize_filename as svc_sanitize
        from api.services.safe_paths import sanitize_filename

        for raw in ("a/b.py", "win\\path\\file.py", "demo.py"):
            assert svc_sanitize(raw) == sanitize_filename(raw)
