"""Wave 5-K — Markdown 인라인 이스케이프 안전성 테스트.

``ReportGenerator.generate_markdown()`` 가 메타데이터, 취약점 블록,
패치 블록, 의존성 블록에 들어오는 사용자 제어 inline 문자열에 대해
다음 침해를 차단하는지 검증한다:

1) ``<script>`` 등 raw HTML 을 Markdown 본문에 그대로 흘려보내지 않음
   (Markdown 렌더러는 paragraph/list 안 raw HTML 을 통과시키므로 위험).
2) ``\\n## injected`` 같이 개행 다음 H2 헤딩이 새로 생기지 않음
   (필드 안 newline 은 모두 공백으로 평탄화되어야 함).
3) 사용자 입력에 들어 있는 ```` ``` ```` 가 새 fenced code block 을
   만들지 않음.
4) ``` `value` ``` 인라인 코드 스팬 안에 사용자 백틱이 그대로 들어가
   스팬을 종료시키지 않음.

본 wave 는 reports/report_generator.py 의 inline-safe 헬퍼만 추가/조정
하며 ``shared/schemas.py`` 는 손대지 않는다.
"""

from __future__ import annotations

from reports.report_generator import ReportGenerator


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _strip_bare_fenced_blocks(md: str) -> str:
    """``generate_markdown`` 이 생성한 bare ```` ``` ```` 펜스 안쪽 라인을
    제거한 사본을 반환.

    fixed_code / code_snippet 본문은 코드 블록 안에 들어가므로
    raw ``<script>`` 등이 그 안쪽에 남아 있어도 Markdown 렌더러에서
    HTML 로 해석되지 않는다. 따라서 "Markdown 본문에 raw HTML 이 노출
    되지 않는다" 라는 invariant 는 코드 블록 외부 영역에 한해서만 확인
    한다.
    """
    kept: list[str] = []
    in_fence = False
    for line in md.split("\n"):
        if line.strip() == "```":
            in_fence = not in_fence
            continue
        if not in_fence:
            kept.append(line)
    return "\n".join(kept)


def _malicious_payload() -> dict:
    """raw HTML, 헤딩 주입, 펜스 주입, 파이프, 백틱이 모두 들어 있는 입력."""
    return {
        "session_id": "sess\n## hacked-session",
        "repo": "octo/<script>alert('repo')</script>",
        "pr_number": "42|cell",
        "branch": "feat/`branch`",
        "commit_sha": "abc`def`123",
        "summary": {
            "total": 1, "high": 1, "medium": 0, "low": 0,
            "patches_generated": 1, "patches_verified": 0,
        },
        "vulnerabilities": [
            {
                "id": "vuln`id`x",
                "tool": "bandit\n## hacked-tool",
                "rule_id": "B`6`08",
                "severity": "HIGH",
                "title": "<script>alert('title')</script>",
                "description": (
                    "desc with <script>alert('desc')</script>\n"
                    "```evil-fence\n"
                    "still bad"
                ),
                "file_path": "src/<script>alert('path')</script>.py",
                "line_number": 99,
                "cwe_id": "CWE-89",
                "code_snippet": "q = 'SELECT * FROM t'",
            }
        ],
        "patches": [
            {
                "vulnerability_id": "vuln`id`x",
                "fix_type": "secure`refactor`",
                "status": "verified",
                "fixed_code": "y = 1",
                "explanation": (
                    "Use parameterized queries\n"
                    "## heading-via-newline\n"
                    "```py\nimport os\n```\n"
                    "and avoid <script>alert('exp')</script>."
                ),
            }
        ],
    }


# ---------------------------------------------------------------------------
# 1) 메타데이터/취약점/패치 inline 필드의 raw HTML + heading/fence 차단
# ---------------------------------------------------------------------------


def test_markdown_metadata_neutralizes_raw_html_and_heading_injection():
    md = ReportGenerator().generate_markdown(_malicious_payload())
    body_outside_code = _strip_bare_fenced_blocks(md)

    # raw <script> 태그가 코드 블록 외부에 노출되어선 안 된다.
    assert "<script>" not in body_outside_code
    assert "</script>" not in body_outside_code

    # newline 주입으로 새 H2 가 만들어져선 안 된다 (필드 안 \n 은 모두
    # 공백으로 평탄화돼야 한다).
    assert "\n## hacked-session" not in md
    assert "\n## hacked-tool" not in md
    assert "\n## heading-via-newline" not in md

    # 사용자 입력의 triple-backtick 이 새 fenced block 을 시작해선 안 된다.
    assert "\n```evil-fence" not in md
    assert "\n```py" not in md

    # 안전 escape 된 형태는 어딘가에 등장해야 한다 (값을 결국 출력하므로).
    assert "&lt;script&gt;" in md


def test_markdown_vulnerability_and_patch_block_neutralize_user_html():
    md = ReportGenerator().generate_markdown(_malicious_payload())
    body_outside_code = _strip_bare_fenced_blocks(md)

    # vulnerability fields
    assert "<script>alert('title')</script>" not in body_outside_code
    assert "<script>alert('desc')</script>" not in body_outside_code
    assert "<script>alert('path')</script>" not in body_outside_code
    # patch fields
    assert "<script>alert('exp')</script>" not in body_outside_code


# ---------------------------------------------------------------------------
# 2) 인라인 코드 스팬 안 사용자 백틱 차단
# ---------------------------------------------------------------------------


def test_markdown_inline_code_spans_drop_user_supplied_backticks():
    md = ReportGenerator().generate_markdown(_malicious_payload())

    # session_id, repo, branch, commit_sha, pr_number 는 모두 ` ... ` 로
    # 감싸 렌더링된다. 사용자 입력에 들어 있는 백틱이 그대로 살아남으면
    # 스팬이 깨지고 그 뒤에 임의 Markdown 이 주입될 수 있다.
    # 따라서 다음 raw 시퀀스들은 출력에 나타나선 안 된다.
    assert "abc`def`123" not in md             # commit_sha
    assert "feat/`branch`" not in md           # branch
    assert "`vuln`id`x`" not in md             # vulnerability id (in `...`)

    # tool / rule_id / file_path 도 마찬가지로 ` ... ` 안에 들어간다.
    assert "B`6`08" not in md                  # rule_id
    # patch.fix_type 도 ` ... ` 안.
    assert "secure`refactor`" not in md
    # patch.vulnerability_id 도 ` ... ` 안.
    # (위 vuln id assert 와 동일한 raw 시퀀스를 공유한다.)


# ---------------------------------------------------------------------------
# 3) 의존성 블록 inline 안전성
# ---------------------------------------------------------------------------


def test_markdown_dependency_block_neutralizes_user_html_and_backticks():
    deps_data = {
        "results": [
            {
                "tool": "pip-audit",
                "vulnerabilities": [
                    {
                        "package": "evil`pkg`",
                        "installed_version": "1.0|0",
                        "fixed_version": "<script>2.0</script>",
                        "severity": "HIGH\n## injected-dep-h2",
                        "vulnerability_id": "CVE-`2024`-9999",
                    }
                ],
            }
        ]
    }
    md = ReportGenerator().generate_markdown(
        {"summary": {"total": 0, "high": 0, "medium": 0, "low": 0,
                     "patches_generated": 0, "patches_verified": 0}},
        deps_data=deps_data,
    )
    body_outside_code = _strip_bare_fenced_blocks(md)

    # raw <script> 미노출.
    assert "<script>2.0</script>" not in body_outside_code
    assert "&lt;script&gt;2.0&lt;/script&gt;" in md
    # severity newline 으로 H2 헤딩이 만들어지면 안 된다.
    assert "\n## injected-dep-h2" not in md
    # package / vulnerability_id 의 backtick 이 인라인 코드 스팬을 깨면
    # 안 된다.
    assert "evil`pkg`" not in md
    assert "CVE-`2024`-9999" not in md


# ---------------------------------------------------------------------------
# 4) 정상 동작 보존: 빈 입력 fallback / 코드 블록 안전성
# ---------------------------------------------------------------------------


def test_markdown_empty_input_keeps_existing_fallback_text():
    md = ReportGenerator().generate_markdown({})
    # Wave 5-J 가 도입한 fallback 문구가 그대로 유지돼야 한다.
    assert "_탐지된 취약점이 없습니다._" in md
    assert "_생성된 수정안이 없습니다._" in md


def test_markdown_code_block_user_triple_backticks_do_not_open_new_fence():
    """fixed_code/code_snippet 안의 ``` 가 코드 블록을 종료시키면 안 된다.

    ``_md_safe_code()`` 가 ``` 시퀀스를 안전 치환하므로, 코드 블록
    내부에 들어간 ``## bad`` 같은 라인은 헤딩이 되어 본문으로 새어
    나가지 않아야 한다.
    """
    data = {
        "summary": {"total": 1, "high": 1, "medium": 0, "low": 0,
                    "patches_generated": 1, "patches_verified": 0},
        "vulnerabilities": [
            {
                "id": "v1", "tool": "bandit", "rule_id": "B608",
                "severity": "HIGH", "title": "t", "description": "d",
                "file_path": "a.py", "line_number": 1, "cwe_id": "CWE-89",
                "code_snippet": "x = 1\n```\n## injected-via-snippet\n",
            }
        ],
        "patches": [
            {
                "vulnerability_id": "v1",
                "fix_type": "secure", "status": "ok",
                "fixed_code": "y = 1\n```\n## injected-via-fixed\n",
                "explanation": "e",
            }
        ],
    }
    md = ReportGenerator().generate_markdown(data)
    body_outside_code = _strip_bare_fenced_blocks(md)

    # 코드 블록을 빠져나와 본문 헤딩으로 살아나선 안 된다.
    assert "## injected-via-snippet" not in body_outside_code
    assert "## injected-via-fixed" not in body_outside_code
