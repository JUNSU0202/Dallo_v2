"""
LLM 에이전트 (agent/llm_agent.py)

정적 분석 결과(VulnerabilityReport)를 받아서
LLM에 전달하고, 수정안(PatchSuggestion)을 반환합니다.

메인 프로바이더: Gemini (무료 API 키 로테이션, 비용 효율)
기타 프로바이더(OpenAI, Anthropic)는 agent/providers/로 이동하여 비활성화 상태로 보존.

사용법:
  from agent.llm_agent import DalloAgent

  agent = DalloAgent(provider="gemini")  # 기본값
  patches = agent.generate_patches(vulnerabilities)
"""

import os
import re
import sys
import time
import logging
from typing import Callable, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.schemas import VulnerabilityReport, PatchSuggestion, PatchStatus
from shared.masking import DataMasker
from agent.provider_factory import get_provider
from agent.providers.base import LLMProvider, SYSTEM_PROMPT

logger = logging.getLogger(__name__)


class DalloAgent:
    """
    LLM 기반 코드 분석 및 리팩토링 에이전트 (Facade)

    Provider 인터페이스를 통해 LLM을 호출합니다.
    프롬프트 구성, 응답 파싱, 민감정보 마스킹, 재시도 로직을 담당합니다.

    재시도 sleep 경계는 생성자 주입형 ``sleeper`` seam 으로 분리되어 있다
    (Wave 4-M). 기본값은 ``time.sleep`` 이며, 테스트에서는 가짜 sleeper 를
    주입하여 실제 wall-clock 대기 없이 rate-limit 재시도 경로를 검증할 수
    있다. ``sleeper`` 는 keyword-only/optional 이라 기존 호출자의 시그니처
    호환은 유지된다.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_keys: Optional[list[str]] = None,
        model: Optional[str] = None,
        provider: str = None,
        max_retries: int = 2,
        temperature: float = 0.2,
        *,
        sleeper: Optional[Callable[[float], None]] = None,
    ):
        self.max_retries = max_retries
        self._masker = DataMasker()

        # Provider Factory를 통해 프로바이더 인스턴스 생성
        self._provider: LLMProvider = get_provider(
            name=provider,
            api_key=api_key,
            api_keys=api_keys,
            model=model,
            temperature=temperature,
        )
        self.provider = (provider or "gemini").lower()
        self.model = self._provider.model
        self.temperature = self._provider.temperature
        # Wave 4-M: retry sleep 경계 — 기본은 time.sleep, 테스트는 fake 주입.
        self._sleeper: Callable[[float], None] = sleeper or time.sleep

    def generate_patch(self, vuln: VulnerabilityReport) -> PatchSuggestion:
        """
        취약점 1건에 대한 수정안을 생성합니다.

        Args:
            vuln: VulnerabilityReport 객체

        Returns:
            PatchSuggestion: 수정된 코드 + 설명
        """
        # 민감정보 마스킹 후 프롬프트 생성
        code_to_mask = vuln.function_code or vuln.code_snippet or ""
        mask_result = self._masker.mask(code_to_mask)
        if mask_result.masked_count > 0:
            logger.info(f"  민감정보 마스킹: {self._masker.get_summary(mask_result)}")
            # 마스킹된 코드로 임시 교체
            original_function = vuln.function_code
            original_snippet = vuln.code_snippet
            if vuln.function_code:
                vuln.function_code = mask_result.masked_text
            else:
                vuln.code_snippet = mask_result.masked_text

        prompt = self._build_prompt(vuln)

        # 원본 복원
        if mask_result.masked_count > 0:
            vuln.function_code = original_function
            vuln.code_snippet = original_snippet

        for attempt in range(self.max_retries + 1):
            try:
                response = self._provider.call(prompt, system=SYSTEM_PROMPT)
                fixed_code, explanation = self._parse_response(response)

                # LLM 응답에서 마스킹 복원
                if mask_result.masked_count > 0:
                    fixed_code = self._masker.unmask(fixed_code, mask_result.mask_map)
                    explanation = self._masker.unmask(explanation, mask_result.mask_map)

                if not fixed_code.strip():
                    raise ValueError("LLM이 빈 코드를 반환했습니다.")

                return PatchSuggestion(
                    vulnerability_id=vuln.id,
                    fixed_code=fixed_code,
                    explanation=explanation,
                    fix_type="recommended",
                    status=PatchStatus.GENERATED,
                )
            except Exception as e:
                err_str = str(e)
                logger.warning(f"[시도 {attempt+1}/{self.max_retries+1}] 수정안 생성 실패: {e}")

                # Rate limit 감지 시 키 전환 또는 대기
                if "429" in err_str or "quota" in err_str.lower():
                    if self._provider.rotate_key():
                        logger.info(f"  Rate limit → 다른 API 키로 전환")
                    else:
                        wait = self._extract_retry_delay(err_str)
                        logger.info(f"  Rate limit 감지 — {wait}초 대기 중...")
                        self._sleeper(wait)

                if attempt == self.max_retries:
                    return PatchSuggestion(
                        vulnerability_id=vuln.id,
                        fixed_code="",
                        explanation=f"수정안 생성 실패 ({self.max_retries+1}회 시도): {str(e)}",
                        status=PatchStatus.FAILED,
                    )

    @staticmethod
    def _extract_retry_delay(error_msg: str) -> int:
        """에러 메시지에서 retry delay 초를 추출합니다."""
        match = re.search(r"retry in (\d+)", error_msg, re.IGNORECASE)
        if match:
            return int(match.group(1)) + 2  # 여유 2초 추가
        return 30  # 기본 30초 대기

    def generate_multi_patches(self, vuln: VulnerabilityReport) -> list[PatchSuggestion]:
        """
        취약점 1건에 대해 3가지 수정안을 생성합니다.

        - minimal: 최소한의 변경으로 취약점만 제거
        - recommended: 보안 모범 사례를 적용한 권장 수정
        - structural: 구조적 개선을 포함한 근본적 해결

        Returns:
            list[PatchSuggestion]: 3가지 수정안 (실패 시 1개만 반환될 수 있음)
        """
        prompt = self._build_multi_prompt(vuln)

        for attempt in range(self.max_retries + 1):
            try:
                response = self._provider.call(prompt, system=SYSTEM_PROMPT)
                patches = self._parse_multi_response(response, vuln.id)

                if not patches:
                    raise ValueError("LLM이 수정안을 반환하지 않았습니다.")

                return patches
            except Exception as e:
                err_str = str(e)
                logger.warning(f"[시도 {attempt+1}/{self.max_retries+1}] 다중 수정안 생성 실패: {e}")

                if "429" in err_str or "quota" in err_str.lower():
                    if self._provider.rotate_key():
                        logger.info(f"  Rate limit → 다른 API 키로 전환")
                    else:
                        wait = self._extract_retry_delay(err_str)
                        logger.info(f"  Rate limit 감지 — {wait}초 대기 중...")
                        self._sleeper(wait)

                if attempt == self.max_retries:
                    # 다중 실패 시 단일 수정안으로 폴백
                    single = self.generate_patch(vuln)
                    return [single]

    def generate_patches(
        self,
        vulnerabilities: list[VulnerabilityReport],
        multi: bool = False,
    ) -> list[PatchSuggestion]:
        """여러 취약점에 대해 일괄 수정안 생성"""
        patches = []
        for i, vuln in enumerate(vulnerabilities):
            logger.info(f"[{i+1}/{len(vulnerabilities)}] {vuln.rule_id} ({vuln.severity}) 처리 중...")
            if multi:
                result = self.generate_multi_patches(vuln)
                patches.extend(result)
            else:
                patch = self.generate_patch(vuln)
                patches.append(patch)
            logger.info(f"  → {len(patches)}건 생성됨")
        return patches

    def _detect_language(self, vuln: VulnerabilityReport) -> str:
        """파일 확장자에서 언어를 감지합니다."""
        import os
        ext_map = {
            ".py": "Python", ".java": "Java", ".js": "JavaScript",
            ".ts": "TypeScript", ".go": "Go", ".c": "C", ".cpp": "C++",
            ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".kt": "Kotlin",
            ".rs": "Rust", ".swift": "Swift", ".scala": "Scala",
        }
        ext = os.path.splitext(vuln.file_path)[1].lower()
        return ext_map.get(ext, vuln.language if hasattr(vuln, 'language') else "Python")

    def _build_prompt(self, vuln: VulnerabilityReport) -> str:
        """취약점 정보를 기반으로 LLM 프롬프트를 구성합니다."""
        code = vuln.function_code or vuln.code_snippet
        cleaned_code = self._strip_line_numbers(code)
        imports = vuln.file_imports or "(없음)"
        lang = self._detect_language(vuln)

        prompt = f"""당신은 보안 코드 리뷰 전문가입니다. 아래 {lang} 코드의 보안 취약점을 분석하고 수정된 코드를 제공하세요.

## 취약점 정보
- 언어: {lang}
- 규칙: {vuln.rule_id} ({vuln.title})
- 심각도: {vuln.severity}
- 설명: {vuln.description}
- CWE: {vuln.cwe_id or 'N/A'}
- 파일: {vuln.file_path}:{vuln.line_number}

## Import 문
```
{imports}
```

## 취약한 코드
```
{cleaned_code}
```

## 요청사항
1. 위 취약점을 수정한 안전한 {lang} 코드를 작성하세요.
2. 기존 기능(비즈니스 로직)은 유지하면서 보안만 강화하세요.
3. 수정 근거를 간단히 설명하세요.
4. 수정 코드는 바로 적용 가능해야 합니다.

## 응답 형식 (반드시 아래 형식을 지켜주세요)
### 수정된 코드
```
(여기에 수정된 전체 함수 코드를 작성하세요. 줄번호 없이 순수 {lang} 코드만 작성하세요.)
```

### 수정 근거
(여기에 수정 이유를 설명하세요)
"""
        return prompt

    def _build_multi_prompt(self, vuln: VulnerabilityReport) -> str:
        """3가지 수정 옵션을 요청하는 프롬프트"""
        code = vuln.function_code or vuln.code_snippet
        cleaned_code = self._strip_line_numbers(code)
        imports = vuln.file_imports or "(없음)"
        lang = self._detect_language(vuln)

        prompt = f"""당신은 보안 코드 리뷰 전문가입니다. 아래 {lang} 코드의 보안 취약점에 대해 **3가지 수정 방안**을 제시하세요.

## 취약점 정보
- 언어: {lang}
- 규칙: {vuln.rule_id} ({vuln.title})
- 심각도: {vuln.severity}
- 설명: {vuln.description}
- CWE: {vuln.cwe_id or 'N/A'}
- 파일: {vuln.file_path}:{vuln.line_number}

## Import 문
```
{imports}
```

## 취약한 코드
```
{cleaned_code}
```

## 요청사항
아래 3가지 수정 방안을 각각 제시하세요. 각 방안마다 수정된 코드와 설명을 포함하세요.

### 옵션 1: 최소 수정 (Minimal Fix)
가장 적은 변경으로 취약점만 제거하는 방법입니다.

```
(수정된 코드)
```
설명: (왜 이렇게 수정했는지)

### 옵션 2: 권장 수정 (Recommended Fix)
보안 모범 사례를 적용한 권장 수정 방법입니다.

```
(수정된 코드)
```
설명: (왜 이렇게 수정했는지)

### 옵션 3: 구조적 개선 (Structural Fix)
코드 구조를 개선하여 근본적으로 취약점을 해결하는 방법입니다.

```
(수정된 코드)
```
설명: (왜 이렇게 수정했는지)
"""
        return prompt

    def _parse_multi_response(self, response: str, vuln_id: str) -> list[PatchSuggestion]:
        """LLM 응답에서 3가지 수정안을 추출합니다."""
        fix_types = [
            ("minimal", "최소 수정", r"옵션\s*1[:\s].*?(?:Minimal|최소)"),
            ("recommended", "권장 수정", r"옵션\s*2[:\s].*?(?:Recommend|권장)"),
            ("structural", "구조적 개선", r"옵션\s*3[:\s].*?(?:Structural|구조)"),
        ]

        # 옵션별로 분리
        sections = re.split(r"###\s*옵션\s*\d", response)
        patches = []

        for i, (fix_type, label, _) in enumerate(fix_types):
            section_idx = i + 1  # sections[0]은 헤더
            if section_idx >= len(sections):
                continue

            section = sections[section_idx]
            code_matches = re.findall(r"```(?:\w*)\s*\n(.*?)```", section, re.DOTALL)
            code = code_matches[0].strip() if code_matches else ""

            # 설명 추출
            explanation = ""
            exp_match = re.search(r"설명[:\s]*(.*?)(?:\n###|\n```|$)", section, re.DOTALL)
            if exp_match:
                explanation = exp_match.group(1).strip()
            if not explanation:
                # 코드 블록 이후 텍스트
                last_block = section.rfind("```")
                if last_block != -1:
                    explanation = section[last_block + 3:].strip()

            if code:
                patches.append(PatchSuggestion(
                    vulnerability_id=vuln_id,
                    fixed_code=code,
                    explanation=f"[{label}] {explanation}" if explanation else f"[{label}]",
                    fix_type=fix_type,
                    status=PatchStatus.GENERATED,
                ))

        # 아무것도 못 파싱했으면 단일 파싱 시도
        if not patches:
            code, explanation = self._parse_response(response)
            if code:
                patches.append(PatchSuggestion(
                    vulnerability_id=vuln_id,
                    fixed_code=code,
                    explanation=explanation,
                    fix_type="recommended",
                    status=PatchStatus.GENERATED,
                ))

        return patches

    @staticmethod
    def _strip_line_numbers(code: str) -> str:
        """코드에서 줄번호 접두사를 제거합니다. (예: '  13 | def...' → 'def...')"""
        lines = code.split("\n")
        cleaned = []
        for line in lines:
            # "  13 | code" 또는 "13 | code" 패턴 감지
            match = re.match(r"^\s*\d+\s*\|\s?(.*)$", line)
            if match:
                cleaned.append(match.group(1))
            else:
                cleaned.append(line)
        return "\n".join(cleaned)

    def _parse_response(self, response: str) -> tuple[str, str]:
        """
        LLM 응답에서 수정 코드와 설명을 추출합니다.

        Returns:
            (fixed_code, explanation) 튜플
        """
        fixed_code = ""
        explanation = ""

        # 전략 1: "수정된 코드" 헤더 뒤의 코드 블록 (어떤 언어든)
        header_code_pattern = r"(?:수정된\s*코드|Fixed\s*Code).*?\n```(?:\w*)?\s*\n(.*?)```"
        match = re.search(header_code_pattern, response, re.DOTALL | re.IGNORECASE)
        if match:
            fixed_code = match.group(1).strip()

        # 전략 2: 모든 코드 블록 중 마지막 (python, java, javascript, go, c, cpp 등)
        if not fixed_code:
            code_matches = re.findall(r"```\w*\s*\n(.*?)```", response, re.DOTALL)
            if code_matches:
                fixed_code = code_matches[-1].strip()

        # 전략 3: 언어 태그 없는 코드 블록
        if not fixed_code:
            code_matches = re.findall(r"```\s*\n(.*?)```", response, re.DOTALL)
            if code_matches:
                fixed_code = code_matches[-1].strip()

        # 설명 추출
        explanation_patterns = [
            r"###?\s*수정\s*근거\s*\n(.*?)(?:\n###|\n```|$)",
            r"수정\s*근거[:\s]*\n(.*?)(?:\n###|\n```|$)",
            r"###?\s*(?:설명|Explanation)\s*\n(.*?)(?:\n###|\n```|$)",
        ]
        for pattern in explanation_patterns:
            m = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
            if m:
                explanation = m.group(1).strip()
                break

        # 설명 폴백: 마지막 코드 블록 이후 텍스트
        if not explanation:
            last_code_end = response.rfind("```")
            if last_code_end != -1:
                remaining = response[last_code_end + 3:].strip()
                # 코드 블록 이전 텍스트도 확인
                if not remaining:
                    first_code_start = response.find("```")
                    if first_code_start > 0:
                        remaining = response[:first_code_start].strip()
                if remaining:
                    explanation = remaining

        if not explanation:
            explanation = "LLM이 수정 근거를 제공하지 않았습니다."

        return fixed_code, explanation


# CLI에서 직접 테스트할 수 있도록
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Dallo LLM Agent 테스트")
    parser.add_argument("--provider", default="gemini", choices=["gemini", "openai", "anthropic"])
    parser.add_argument("--model", default=None)
    parser.add_argument("--api-key", default=None)
    args = parser.parse_args()

    # 테스트용 취약점 생성
    test_vuln = VulnerabilityReport(
        id="test_vuln_001",
        tool="bandit",
        rule_id="B608",
        severity="HIGH",
        confidence="HIGH",
        title="SQL Injection",
        description="Possible SQL injection via string-based query construction.",
        file_path="test_targets/sql_injection.py",
        line_number=10,
        code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
        function_code='''def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()''',
        file_imports="import sqlite3",
        cwe_id="CWE-89",
    )

    agent = DalloAgent(
        api_key=args.api_key,
        model=args.model,
        provider=args.provider,
    )

    print(f"프로바이더: {agent.provider}, 모델: {agent.model}")
    print("=" * 60)
    patch = agent.generate_patch(test_vuln)
    print(f"상태: {patch.status}")
    print(f"\n수정 코드:\n{patch.fixed_code}")
    print(f"\n설명:\n{patch.explanation}")
