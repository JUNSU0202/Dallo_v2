# Wave 5-N Red/Blue Audit Recipe Adaptation

> 본 문서는 **Wave 5-N** 의 합리화 노트(rationale note)다. 본 wave 는 `/home/ubuntu/dallo_redblue_audit_recipe.md` 의 audit recipe 와 Gusle01 커밋 `f005625` / `e474680` 의 **기능 의도(feature intent)** 만 Dallo_v2 의 클린 아키텍처(라우터 / 서비스 / 도메인 / 어댑터 / seam) 위에서 다시 구현(backport-by-rewrite)한 결과를 기록한다.
> 본 wave 는 *구현·검증 단계에서는* 머지 / 푸시 / 배포 / 리셋 / 워크트리 삭제를 수행하지 않는다. 본 문서는 그 단계의 **읽기 전용 합리화 기록** 이다. (사용자의 명시적 승인 이후 수행된 원격 출하 기록은 §6 — Post-delivery — 참고.)

---

## 1. 배경 (Adaptation source)

- **Recipe**: `/home/ubuntu/dallo_redblue_audit_recipe.md` — Wave 5-G / 5-H / 5-L / 5-M 이 출하한 자산(`DalloAgent.audit_code`, heuristic fallback, quick scan 정책, `llm_audit_when_clean` plumbing) 을 한 번에 “정상(clean) 정적 분석 시 LLM 보조 감사 → 취약점 승격 → Blue Team 패치 생성” 흐름으로 묶는 작업 레시피. Gusle01 의 `f005625` (feat: add red blue ai audit workflow) 와 `e474680` (clean audit hardening) 두 커밋의 의도를 본 레시피가 통합한다.
- **클린 아키텍처 적용 원칙**:
  - 옛 모놀리스(`api/server.py`) 변경 없음 — 본 wave 가 손대는 운영 코드는 라우터 / 서비스 / 도메인 / 어댑터 레이어로 한정한다.
  - LLM 기본 경로는 Google AI Studio / Gemini 유지. `gateway` 프로바이더 / `claude-sonnet-4-6` 디폴트는 본 wave 에서도 도입하지 않는다.
  - 모든 변경은 fake-seam 단위 테스트 + 회귀 가드 + 단일 머지 커밋으로 revertable.

---

## 2. 구현 범위 (Implemented scope)

본 wave 가 실제로 코드에 반영한 항목은 다음과 같다.

1. **`e474680` 보강 — `enrich_patch` 빈 Blue Team 메타데이터 채움**
   - `shared/red_blue.py::enrich_patch` 가 Blue Team 메타데이터 필드(`blue_team_phase`, `defense_strategy`, `defense_outcome`, `residual_risk`, `defense_plan`) 가 빈 문자열(`""`) 또는 빈 dict 로 들어올 때, 해당 필드를 `PatchSuggestion.to_dict()` 의 디폴트 값으로 채워 넣도록 보강했다. 누락된 필드가 응답 contract 의 빈 값 그대로 새어 나가던 경로를 차단한다.
   - **Risk reduction 보강** — `build_defense_comparison` 이 `security_revalidation.passed=True` + `removed_count=0` + 비어 있지 않은 `fixed_code` 의 조합을 최소 1 건의 fixed finding 으로 집계한다. 제거된 취약점 카운트가 0 이어도 실제로 코드가 패치된 사례를 Red/Blue 비교에 반영한다.
   - 회귀 가드: `tests/test_shared_red_blue.py` 의 신규 케이스가 빈 메타데이터 채움 / verified-zero-removed-with-fixed-code 두 시나리오를 모두 가드한다.

2. **AUTH-BYPASS 집계(`match_mode="all_file"`) 룰 — quick scan ↔ heuristic 통합**
   - `analyzer/quick_scan.py` 와 `analyzer/heuristic_runner.py` 가 단일 라인 매칭이 아니라 **분석 대상 동일 파일 안에서 세 가지 AUTH-BYPASS 마커가 모두 등장** 할 때만 CWE-288 finding 을 생성하도록 통합했다 (`match_mode="all_file"`).
   - 기존 정규식 규칙 메타데이터의 의도를 유지하면서, 두 모듈이 동일한 입력 정규화 규칙을 공유한다. 세 마커가 같은 파일 안에 모두 존재해야 트리거되며, 일부만 일치하는 파일에는 finding 이 생성되지 않는다.
   - 이로써 Wave 5-H 가 도입한 heuristic fallback 과 quick scan 의 정책이 한 곳에서 어긋나지 않는다.

3. **`DalloAgent.audit_code()` — 정상(clean) 정적 분석 시 LLM 보조 감사**
   - `agent/llm_agent.py` 에 `audit_code(...)` 메서드를 추가/정규화했다. 입력은 `code` / `filename` / `language` (필수) 및 옵션 `max_chars` 인자이며, 출력은 `status` / `summary` / `findings[]` 형태의 정규화된 감사 dict 이고, 각 finding 은 `title` / `cwe_id` / `severity` / `line_number` / `evidence` / `reason` / `recommendation` 키를 갖는다. Gemini fake provider 단위 테스트로만 검증한다 (실 LLM 호출 0).
   - 본 메서드는 *옵트인* 이다. 기본 경로(정적 분석이 finding 을 1 개라도 낸 경우) 에서는 호출되지 않는다.

4. **`llm_audit_when_clean` 흐름 — API / 서비스 / Celery / 파이프라인 plumbing**
   - `api/routers/analyze.py::AnalyzeRequest` 에 `llm_audit_when_clean` 옵션을 keyword-only 로 추가(디폴트 `False`).
   - `api/services/analysis_pipeline.py::execute_analysis_job` 와 `api/tasks.py::run_analysis_task` 가 해당 옵션을 Celery task 시그니처를 거쳐 `analyzer/pipeline.py::execute_pipeline` 까지 전달한다.
   - 파이프라인은 **정적 분석이 정상(빈 finding) 일 때만** `DalloAgent.audit_code()` 를 호출하고, 결과 finding 을 응답 `vulnerabilities` 리스트에 *승격(promotion)* 시킨다. 승격된 항목은 `shared.red_blue.enrich_vulnerability` 를 거쳐 Red Team enrichment 를 받으며, 이어지는 Blue Team 패치 생성 경로(`DalloAgent.generate_patches`) 가 그대로 패치 후보를 만든다.
   - `enrich_patch` 의 1번 보강(빈 Blue Team 메타데이터 채움 / `build_defense_comparison` 의 fixed finding 집계) 이 이 경로의 끝단에서 한 번 더 작동해, “LLM audit → 취약점 승격 → Blue Team 패치” 사슬이 안전하게 마감된다.

---

## 3. 의식적인 보존 / 미채택 (Intentional preservations & omissions)

본 wave 는 다음을 의식적으로 *하지 않는다*. 본 절은 향후 회귀 / 검토 시점에 의사결정 근거가 된다.

- **Gusle01 gateway 디폴트 / 프로바이더 백포트 미채택** — `agent/providers/gateway_provider.py` 도입, `provider_factory` 활성화, `AnalyzeRequest` 의 `provider` / `model` 디폴트 변경(`"gateway"` / `"claude-sonnet-4-6"`) 은 Wave 5-A §6-1 의 Hard Reject 정책 그대로 본 wave 에서도 채택하지 않는다. Gemini / Google AI Studio 기본 경로가 유지된다.
- **`api/server.py` 모놀리스 변경 없음** — 본 wave 는 server.py 의 라인을 추가/수정하지 않는다. 모든 변경은 `api/routers/analyze.py` / `api/services/analysis_pipeline.py` / `api/tasks.py` / `analyzer/pipeline.py` / `agent/llm_agent.py` / `shared/red_blue.py` / `analyzer/quick_scan.py` / `analyzer/heuristic_runner.py` 로 한정되며, 라우터/서비스 분리(Wave 2-B ~ 4-Z) 가 그대로 보존된다.
- **`shared/schemas.py` 무변경** — Wave 5-A §6-2 / §10 의 “스키마 변경은 별도 명시 승인 후에만” 정책 그대로. `llm_audit_when_clean` 옵션과 승격된 finding 은 모두 기존 응답 contract 안에서 처리된다.
- **구현 / 검증 단계의 푸시 / 배포 / 워크트리 삭제 없음** — 본 wave 는 *구현·검증 단계*에서 로컬 브랜치 `w5n-redblue-audit-recipe` 위에서만 작업하며, 그 단계에서는 `git push` / 배포 파이프라인 / `git worktree remove` / `git reset --hard` / `git clean -f` / 원격 브랜치 / PR 생성 모두 수행하지 않는다. (사용자 승인 이후 `dallo_v2/main` 으로의 원격 출하는 §6 참고.)

---

## 4. 검증 요약 (Verification summary — Hermes runs)

본 절은 본 wave 의 코드 변경이 실제로 통과한 검증을 기록한다. 모든 수치는 본 wave 중 Hermes 가 이미 실행한 명령의 결과 그대로다.

| 검증 항목 | 명령 | 결과 |
|---|---|---|
| Baseline full pytest (변경 적용 전) | `pytest tests/ -q` | **1168 passed** |
| Targeted 신규 + 인접 회귀 | `pytest tests/test_shared_red_blue.py tests/test_llm_agent_audit_code.py tests/test_pipeline_clean_audit.py tests/test_quick_scan_policy_seam.py tests/test_api_analyze_router.py tests/test_api_analysis_pipeline_service.py tests/test_api_analyze_lazy_celery.py tests/test_wave5m_user_prompt_and_guardrails.py -q` | **337 passed** |
| Full pytest (변경 적용 후) | `pytest tests/ -q` | **1246 passed** (baseline 1168 → +78 신규 회귀) |
| 변경 모듈 byte-compile | `python -m py_compile` (변경된 운영/테스트 파일 전체) | **pass** |
| Dashboard 빌드 | `cd dashboard && npm ci --include=dev && npm run build` | **pass** (dev deps 포함 설치 후 빌드 그린). `npm audit` 은 production install 에서 high 1 건, dev deps 포함 시 총 3 건의 의존성 취약점을 보고했으나 이는 본 wave 이전부터의 **선존하던 의존성 audit 이슈** 이고 본 wave 에서 자동 수정하지 않는다. |
| FastAPI route smoke | `TestClient` 경유 인증된 `/api/analyze` + `/api/red-blue/summary` 호출 | **PASS** |
| Diff 보안 점검 / secret heuristic | 변경된 diff 의 추가 라인에 대한 secret-like 리터럴 검출 | **PASS** (추가 라인 0) |

- 실 GitHub push / 배포 / 실 LLM / 실 Redis 호출은 본 wave 검증에서 0 건이다. npm registry 는 위 dashboard `npm ci --include=dev && npm run build` 의 의존성 설치 / 빌드 검증 용도로만 접근했다. Celery / agent / runner 는 모두 fake seam 으로 주입된다.
- 본 문서는 외부에 비밀 / 토큰 / API key 를 노출하지 않는다. 모든 테스트 더블은 `monkeypatch` 와 fake provider 만 사용한다.

---

## 5. Rollback 지침 (Rollback)

- *구현·검증 단계 (머지·푸시 이전):* 본 wave 의 변경이 아직 단일 머지 커밋으로 통합되기 전이라면, 로컬 브랜치 `w5n-redblue-audit-recipe` 를 그대로 **포기(abandon)** 하는 것으로 롤백이 끝난다. 이 단계에서는 원격으로 푸시된 적이 없고 머지된 적도 없으므로 운영 영향은 0 이다. (본 시점 이후의 사실은 §6 참고.)
- *머지 이후:* 머지 커밋이 만들어진 뒤 회귀가 필요해지면, `git revert -m 1 <merge_commit>` 으로 단일 커밋 revert 한다. Wave 5-N 의 단일 머지 커밋은 `95988ce` (`merge: integrate Wave 5-N red blue audit workflow`) 이므로, 본 wave 의 머지/출하 롤백은 `git revert -m 1 95988ce` 로 표현된다. 본 wave 의 변경은 모두 옵트인(`llm_audit_when_clean=False` 디폴트) 이고, 응답 contract / 스키마는 무변경이므로 revert 의 운영 caller 영향 또한 0 이다.

---

## 6. 출하 기록 (Post-delivery — user-approved push to Dallo_v2)

본 절은 §1~§5 의 코드 변경 / 검증이 끝난 뒤, **사용자의 명시적 승인** 을 거쳐 수행된 원격 출하 사실을 기록한다. §1~§5 에 등장하는 "푸시 / 배포 / 워크트리 삭제 없음" 표현은 *구현·검증 단계 (implementation-before-delivery)* 에 한정된 서술이며, 본 절은 그 단계 이후의 상태 변화를 정확히 남기는 것을 목적으로 한다.

- **승인 시점 / 절차**: 사용자가 Wave 5-N 의 결과를 `JUNSU0202/Dallo_v2` 로 푸시하는 것을 명시적으로 승인했다. 본 출하는 그 승인 범위 안에서만 수행됐고, 그 외 추가 원격 / 추가 브랜치 / 배포 파이프라인 트리거는 수행하지 않았다.
- **출하 명령**: `git push dallo_v2 main:main` — 성공.
- **로컬 / 원격 동기 상태**: 푸시 직후 원격 `dallo_v2/main` 이 로컬 `main` 과 동일 커밋 `95988ceb9932521b6707c43f7aa51b0859ba619c` 에 위치함을 확인했다.
- **출하 커밋 (short)**: `95988ce` — `merge: integrate Wave 5-N red blue audit workflow` (Wave 5-N 단일 머지 커밋).
- **CI / check-run 상태 (푸시 직후 조회)**: GitHub status query 결과 status state = `pending`, `total_statuses=0`, check-runs `total_count=0`. 이는 *등록된 검사 자체가 0 건* 임을 의미하며 **실패가 아니다**. 본 시점에 등록된 CI 가 없으므로 §4 의 로컬 / Hermes 검증 그린이 출하 시점의 유효한 품질 기록으로 남는다.
- **원격 롤백 명령**: 본 출하의 머지 커밋을 단일 명령으로 되돌리려면 다음을 사용한다.
  ```
  git revert -m 1 95988ce
  ```
  Wave 5-N 의 모든 변경은 옵트인(`llm_audit_when_clean=False` 디폴트) 이고 응답 contract / 스키마는 무변경이므로, 본 revert 의 caller 영향은 0 이다. 원격에 revert 커밋을 반영하려면 동일 원격으로 `git push dallo_v2 main:main` 을 다시 수행한다.

— Wave 5-N 종료.
