"""정규식 기반 빠른 취약점 스캔 (analyzer/quick_scan.py).

Wave 2-C: api/server.py 에서 분리된 순수 도메인 로직 모듈.
프로세스 실행 없이 라인 단위 패턴 매칭만으로 밀리초 단위 응답을 제공한다.

설계 원칙:
- FastAPI / DB / 외부 I/O 의존 없음 (analyzer 패키지의 다른 모듈과 동일).
- 룰 정의(QUICK_SCAN_RULES) 와 헬퍼(_detect_language, scan)만 노출한다.
- 라우터는 api/routers/quick_scan.py 가 이 모듈을 호출한다.
"""

from __future__ import annotations

import os
import re

QUICK_SCAN_RULES = [
    # SQL Injection
    {
        "id": "QS-SQL-INJECT",
        "title": "SQL Injection 가능성",
        "severity": "HIGH",
        "cwe": "CWE-89",
        "patterns": [
            r'f"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b[^"]*\{',
            r"f'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b[^']*\{",
            r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE)\b.*["\']\s*\+',
            r'\.format\(.*\).*(?:execute|query)',
            r'%s.*(?:execute|query)|(?:execute|query).*%\s',
            r'(?:executeQuery|executeUpdate|execute)\([^)]*\+',
            r'(?:query|exec)\([^)]*\+\s*(?:req\.|user)',
            r'"\s*\+\s*\w+\s*\+\s*".*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)',
        ],
        "languages": ["python", "java", "javascript", "go", "php", "ruby"],
        "message": "사용자 입력이 SQL 쿼리에 직접 삽입될 수 있습니다. 파라미터 바인딩을 사용하세요.",
    },
    # Command Injection
    {
        "id": "QS-CMD-INJECT",
        "title": "Command Injection 가능성",
        "severity": "HIGH",
        "cwe": "CWE-78",
        "patterns": [
            r'os\.system\s*\(\s*f["\']',
            r'os\.system\s*\([^)]*\+',
            r'os\.popen\s*\(\s*f["\']',
            r'subprocess\.(?:call|run|Popen)\s*\(\s*f["\']',
            r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True',
            r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+',
            r'exec\s*\(\s*["\'][^"\']*["\']\s*\+',
            r'child_process.*exec\s*\([^)]*\+',
        ],
        "languages": ["python", "java", "javascript", "go", "c", "cpp"],
        "message": "외부 명령어에 사용자 입력이 삽입될 수 있습니다. shlex.quote() 또는 허용 목록을 사용하세요.",
    },
    # Hardcoded Secrets
    {
        "id": "QS-HARDCODED-SECRET",
        "title": "하드코딩된 인증 정보",
        "severity": "HIGH",
        "cwe": "CWE-798",
        "patterns": [
            r'(?:API_KEY|API_SECRET|SECRET_KEY|ACCESS_KEY|PRIVATE_KEY)\s*=\s*["\'][^"\']{8,}["\']',
            r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
            r'(?:token|TOKEN)\s*=\s*["\'][^"\']{8,}["\']',
            r'(?:sk-|ghp_|gho_|AIzaSy|AKIA)[A-Za-z0-9_\-]{10,}',
            r'(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD)\s*=\s*["\'][^"\']+["\']',
        ],
        "languages": ["python", "java", "javascript", "go", "c", "cpp", "ruby", "php", "kotlin", "rust"],
        "message": "인증 정보가 소스코드에 하드코딩되어 있습니다. 환경변수나 시크릿 매니저를 사용하세요.",
    },
    # Weak Hashing
    {
        "id": "QS-WEAK-HASH",
        "title": "취약한 해시 알고리즘",
        "severity": "MEDIUM",
        "cwe": "CWE-328",
        "patterns": [
            r'hashlib\.(?:md5|sha1)\s*\(',
            r'MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-1|SHA1)["\']',
            r'crypto\.create(?:Hash|Hmac)\s*\(\s*["\'](?:md5|sha1)["\']',
            r'MD5\.Create\(\)',
            r'Digest::(?:MD5|SHA1)',
        ],
        "languages": ["python", "java", "javascript", "ruby", "go", "cpp"],
        "message": "MD5/SHA1은 보안 용도에 부적합합니다. SHA-256 이상 또는 bcrypt/argon2를 사용하세요.",
    },
    # XSS
    {
        "id": "QS-XSS",
        "title": "XSS (Cross-Site Scripting) 가능성",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "patterns": [
            r'res\.send\s*\(\s*["\']<[^>]*["\']\s*\+',
            r'document\.write\s*\(',
            r'\.innerHTML\s*=\s*(?![\s]*["\']<)',
            r'v-html\s*=',
            r'dangerouslySetInnerHTML',
            r'\.write\s*\(\s*["\']<.*\+',
        ],
        "languages": ["javascript", "python", "java", "php", "ruby"],
        "message": "사용자 입력이 HTML에 직접 삽입될 수 있습니다. 이스케이프 처리를 적용하세요.",
    },
    # Insecure Deserialization
    {
        "id": "QS-UNSAFE-DESERIAL",
        "title": "안전하지 않은 역직렬화",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "patterns": [
            r'pickle\.loads?\s*\(',
            r'yaml\.load\s*\([^)]*(?!Loader)',
            r'eval\s*\(\s*(?:request|req|input|user)',
            r'unserialize\s*\(\s*\$',
            r'Marshal\.load\s*\(',
        ],
        "languages": ["python", "java", "javascript", "php", "ruby"],
        "message": "신뢰할 수 없는 데이터의 역직렬화는 원격 코드 실행으로 이어질 수 있습니다.",
    },
    # Path Traversal
    {
        "id": "QS-PATH-TRAVERSAL",
        "title": "경로 탐색 취약점",
        "severity": "MEDIUM",
        "cwe": "CWE-22",
        "patterns": [
            r'open\s*\(\s*(?:f["\']|.*\+|.*format|.*%)',
            r'os\.path\.join\s*\([^)]*(?:request|req|input|user)',
            r'readFile(?:Sync)?\s*\([^)]*(?:req\.|user)',
            r'new\s+File\s*\([^)]*\+',
        ],
        "languages": ["python", "java", "javascript", "go", "php"],
        "message": "사용자 입력이 파일 경로에 사용되면 경로 탐색 공격이 가능합니다.",
    },
    # Insecure Random
    {
        "id": "QS-INSECURE-RANDOM",
        "title": "보안에 부적합한 난수 생성",
        "severity": "LOW",
        "cwe": "CWE-330",
        "patterns": [
            r'random\.random\s*\(',
            r'random\.randint\s*\(',
            r'Math\.random\s*\(',
            r'java\.util\.Random\b',
            r'rand\s*\(\s*\)',
        ],
        "languages": ["python", "java", "javascript", "c", "cpp", "go"],
        "message": "보안 목적(토큰, 키 생성)에는 secrets 모듈이나 crypto.randomBytes를 사용하세요.",
    },
    # Wave 5-N: WebGoat VerifyAccount-like Auth Bypass (사용자 제어 ID 흐름).
    # 세 마커가 같은 파일에 모두 등장할 때만 finding 을 생성한다 (all_file).
    # 마지막 패턴(setValue("account-verified-id", ...)) 의 라인이 evidence 로
    # 보고된다 — 인증 우회 결정 지점이라서 가장 유용한 앵커다.
    {
        "id": "QS-AUTH-BYPASS-USER-CONTROLLED-ID",
        "title": "사용자 제어 ID 기반 인증 우회 (WebGoat VerifyAccount 패턴)",
        "severity": "HIGH",
        "cwe": "CWE-288",
        "patterns": [
            r'@RequestParam\s+(?:final\s+)?String\s+userId\b',
            r'verifyAccount\s*\(\s*Integer\.valueOf\s*\(\s*userId\s*\)',
            r'setValue\s*\(\s*"account-verified-id"\s*,\s*userId',
        ],
        "languages": ["java"],
        "match_mode": "all_file",
        "message": (
            "사용자가 제어하는 userId 가 verifyAccount() 와 "
            "setValue(\"account-verified-id\", ...) 흐름에 그대로 흘러가 "
            "인증 우회가 가능합니다. 세션 식별자는 서버 권한 컨텍스트에서 "
            "결정하세요."
        ),
    },
]


_EXT_LANGUAGE_MAP = {
    ".py": "python", ".java": "java", ".js": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".go": "go", ".c": "c",
    ".cpp": "cpp", ".h": "c", ".hpp": "cpp", ".rb": "ruby", ".php": "php",
    ".kt": "kotlin", ".rs": "rust", ".cs": "csharp",
}


def detect_language(filename: str) -> str:
    """파일 이름의 확장자로 언어를 추정한다. 알 수 없으면 'python'."""
    _, ext = os.path.splitext(filename.lower())
    return _EXT_LANGUAGE_MAP.get(ext, "python")


def _rule_match_mode(rule: dict) -> str:
    """룰 메타데이터의 정규 매칭 모드를 'any' | 'all' | 'all_file' 로 반환.

    옵트인 신호:
    - ``require_all=True`` → 'all' (동일 라인 all-pattern 매칭, legacy alias)
    - ``match_mode="all"`` → 'all'
    - ``match_mode="all_file"`` → 'all_file' (파일 전역 all-pattern 매칭;
      Wave 5-N: WebGoat-like AUTH-BYPASS 처럼 마커가 서로 다른 라인에 흩어진
      케이스를 옵트인 매치한다)
    - 그 외 → 'any' (legacy 동작)
    """
    if rule.get("require_all") is True:
        return "all"
    mode = rule.get("match_mode")
    if isinstance(mode, str):
        normalized = mode.lower()
        if normalized in ("all", "all_file"):
            return normalized
    return "any"


def _make_finding(rule: dict, line_num: int, line_text: str) -> dict:
    return {
        "rule_id": rule["id"],
        "title": rule["title"],
        "severity": rule["severity"],
        "cwe": rule["cwe"],
        "line": line_num,
        "code": line_text.strip(),
        "message": rule["message"],
    }


def scan(code: str, language: str) -> list:
    """정규식 기반 빠른 취약점 스캔 (밀리초 단위 응답)."""
    findings: list = []
    lines = code.split("\n")

    for rule in QUICK_SCAN_RULES:
        if language not in rule["languages"]:
            continue

        mode = _rule_match_mode(rule)
        patterns = rule.get("patterns") or ()

        if mode == "all":
            # all-mode: 모든 패턴이 동일 라인에서 매치된 라인에만 finding.
            # 패턴 중 하나라도 invalid regex 면 fail-closed (룰 전체 스킵).
            try:
                regexes = [re.compile(p, re.IGNORECASE) for p in patterns]
            except re.error:
                continue
            if not regexes:
                continue
            for line_num, line_text in enumerate(lines, 1):
                if all(rx.search(line_text) for rx in regexes):
                    findings.append(_make_finding(rule, line_num, line_text))
            continue

        if mode == "all_file":
            # all_file-mode: 모든 패턴이 파일 전역에서 (서로 다른 라인이어도)
            # 한 번 이상 매치되어야 한 건의 finding 을 만든다. invalid regex 가
            # 섞이면 fail-closed (룰 전체 스킵). 룰당 finding 은 최대 1 건.
            # finding 의 line/code 는 패턴 리스트의 *마지막* 패턴의 첫 매치
            # 라인을 사용한다 — 룰 작성자가 가장 specific 한 패턴을 마지막에
            # 두면 그 라인이 evidence 로 보고된다.
            try:
                regexes = [re.compile(p, re.IGNORECASE) for p in patterns]
            except re.error:
                continue
            if not regexes:
                continue
            anchor_matches: list = []
            all_matched = True
            for rx in regexes:
                hit = None
                for line_num, line_text in enumerate(lines, 1):
                    if rx.search(line_text):
                        hit = (line_num, line_text)
                        break
                if hit is None:
                    all_matched = False
                    break
                anchor_matches.append(hit)
            if all_matched and anchor_matches:
                line_num, line_text = anchor_matches[-1]
                findings.append(_make_finding(rule, line_num, line_text))
            continue

        # legacy any-mode: 한 패턴이라도 매치되면 finding, invalid regex 는 스킵.
        for pattern in patterns:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for line_num, line_text in enumerate(lines, 1):
                    if regex.search(line_text):
                        already = any(
                            f["rule_id"] == rule["id"] and f["line"] == line_num
                            for f in findings
                        )
                        if not already:
                            findings.append(_make_finding(rule, line_num, line_text))
            except re.error:
                continue

    findings.sort(key=lambda f: f["line"])
    return findings
