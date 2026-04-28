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


def scan(code: str, language: str) -> list:
    """정규식 기반 빠른 취약점 스캔 (밀리초 단위 응답)."""
    findings: list = []
    lines = code.split("\n")

    for rule in QUICK_SCAN_RULES:
        if language not in rule["languages"]:
            continue
        for pattern in rule["patterns"]:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for line_num, line_text in enumerate(lines, 1):
                    if regex.search(line_text):
                        already = any(
                            f["rule_id"] == rule["id"] and f["line"] == line_num
                            for f in findings
                        )
                        if not already:
                            findings.append({
                                "rule_id": rule["id"],
                                "title": rule["title"],
                                "severity": rule["severity"],
                                "cwe": rule["cwe"],
                                "line": line_num,
                                "code": line_text.strip(),
                                "message": rule["message"],
                            })
            except re.error:
                continue

    findings.sort(key=lambda f: f["line"])
    return findings
