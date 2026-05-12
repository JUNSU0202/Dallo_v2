# Wave 5-A — Red/Blue 백포트 선별 및 아키텍처 계획 (문서 전용)

> 본 문서는 **Wave 5-A** 의 결과물이다.
> Wave 5-A 는 **문서 전용(doc-only) wave** 다. 운영 코드, 테스트, 패키지 파일, 설정 동작, API 코드, 프론트엔드 코드, 스키마 어느 것도 본 wave 에서 변경되지 않는다.
> 본 문서의 목적은 단 하나다 — 원격 `gusle01/main` 브랜치가 가진 Red/Blue 관련 기능을 **어떻게 Dallo_v2 클린 아키텍처 위에 안전하게 다시 구현할 것인가** 를 사전에 합의해 두는 것이다.
> 본 문서는 머지/체리픽/푸시/PR/배포/실 외부 호출 어떤 것도 수행하지 않는다.

---

## 1. 범위 (Scope)

- 본 wave 의 산출물:
  1. `docs/refactoring/redblue-backport-selection.md` (이 파일) — 신규 작성.
  2. (옵션) `docs/refactoring/clean-architecture-wave-history.md` 에 Wave 5-A 짧은 항목 추가.
- 본 wave 가 **하지 않는 것**:
  - `gusle01/main` 으로부터의 merge / cherry-pick.
  - 운영 코드 / 테스트 / 패키지 / 설정 / API / 프론트엔드 / 스키마 변경.
  - 외부 서비스 호출(Gemini, GitHub, Sonar, Bandit 실 실행 등).
  - 푸시 / PR / 배포 / 운영 DB 접근.
- 본 wave 의 산출은 "어떤 기능을 어디에 어떤 순서로 다시 만들 것인가" 에 대한 **읽기 전용 합의문** 이다. 코드 변경은 5-B 이후의 별개 wave 에서, 매번 사용자 명시 승인을 거쳐 진행한다.

---

## 2. 기준 원칙

본 wave 와 그 이후 모든 Red/Blue 관련 wave 는 다음 원칙을 무조건 지킨다.

1. **Dallo_v2 `main` 이 진실의 원천(source of truth)이다.**
   - 로컬 `main` 의 Wave 2-A ~ Wave 4-Z 까지 정리된 라우터/서비스/도메인/어댑터/seam 구조가 기준이다.
   - 원격 `gusle01/main` 은 리팩토링 이전 단계의 모놀리식 코드를 포함하므로, **구조가 아니라 기능 의도(feature intent)만** 가져온다.
2. **Gusle01 의 기능 의도만 채택하고, 옛 구조는 복사하지 않는다.**
   - `api/server.py` 1,152 줄 모놀리스, `analyzer/pipeline.py` 의 직접 `open()`, `analyzer/semgrep_runner.py` 의 직접 `subprocess.run`, 임포트 부수효과(`init_db()` / Redis ping / `sys.path.insert`) 같은 옛 패턴은 한 줄도 가져오지 않는다.
3. **LLM 기본 경로는 Google AI Studio / Gemini 다.**
   - `agent/provider_factory.py` 의 `_ACTIVE_PROVIDERS = {"gemini", "openrouter"}` 와 기본 `PRIMARY_PROVIDER="gemini"`, `api/routers/analyze.py` 의 기본 `provider="gemini" / model="gemini-2.0-flash-lite"` 는 본 wave 와 이후 Red/Blue 백포트 wave 전체에서 **변경 금지** 다.
   - Gusle01 의 `gateway_provider`, `LLM_PRIMARY_PROVIDER=gateway`, `provider="gateway"`, `model="claude-sonnet-4-6"` 는 **거부(Reject) / 보류(Defer)** 한다. 별도 승인 없이 채택하지 않는다.
4. **코드 변경은 작은 wave + 테스트 + 사용자 승인 + revertable 머지 형태로만 한다.**
   - 단일 wave 는 단일 책임을 옮기고, fake seam 기반 테스트가 동반된다.
   - `shared/schemas.py` 같은 **공유 계약(shared contract)** 변경은 항상 명시 승인 후에만 가능하다.
   - 모든 wave 는 머지 커밋 1 개 단위로 revert 가능해야 한다.

---

## 3. Git 사실 (이 문서 작성 시점)

본 문서를 작성한 시점에서 read-only `git` 명령으로 확인한 사실은 다음과 같다.

- 로컬 `main` HEAD: **`cc4b466`** (`docs(refactoring): sync Wave 4-Z post-merge status`).
- 원격 `gusle01/main` HEAD: **`36041cc`** (`docs: update project change log`).
- 두 브랜치의 공통 조상(merge-base): **`ce5e869`**.
- 로컬 `main` 이 merge-base 보다 앞선 커밋 수(local ahead): **147 commits**.
- 원격 `gusle01/main` 이 merge-base 보다 앞선 커밋 수(remote ahead): **4 commits**.
- 원격에서 앞선 4 커밋:
  - `4c2e63b` fix scan persistence and env fallback
  - `5f0d307` docs update log in Korean
  - `f005625` feat: add red blue ai audit workflow
  - `36041cc` docs: update project change log
- `git merge-tree --write-tree main gusle01/main` 가 보고하는 직접 머지 충돌 파일:
  - `analyzer/semgrep_runner.py` (CONFLICT content)
  - `api/server.py` (CONFLICT content)
  - `reports/__init__.py` (CONFLICT add/add)
  - `reports/report_generator.py` (CONFLICT add/add)
  - `update.me` (CONFLICT add/add)

---

## 4. 직접 머지 / 체리픽 판정: **안전하지 않음 (NOT SAFE)**

판단의 근거를 초심자도 따라갈 수 있게 단계별로 풀어 쓴다.

1. **공유 파일에서 줄 단위 충돌이 5 곳 발생한다.**
   - 위 §3 의 `git merge-tree` 결과처럼, `analyzer/semgrep_runner.py` / `api/server.py` / `reports/__init__.py` / `reports/report_generator.py` / `update.me` 다섯 군데에서 두 브랜치가 같은 라인을 서로 다르게 고쳤다.
   - 단순 머지 가능 여부 차원에서도 이미 충돌이 있으므로, 손으로 충돌을 해결하지 않고는 머지 자체가 진행되지 않는다.
2. **충돌이 없는 파일에서도, 직접 머지는 Dallo_v2 가 만들어 둔 새 파일들을 "삭제하는 방향" 으로 적용된다.**
   - 로컬 `main` 이 147 커밋 앞서 있고 원격이 4 커밋 앞서 있는 상태에서, `gusle01/main` 은 merge-base 시점에는 존재하지 않던 클린 아키텍처 파일들을 **알지 못한다**. 따라서 직접 머지/체리픽은 다음 자산을 의도치 않게 삭제/우회한다:
     - `api/routers/*` (Wave 2-B 이후 라우터 분리)
     - `api/services/*` (Wave 2-M / 3-D 이후 서비스 분리)
     - `api/dto/*` (응답 DTO 분리)
     - `api/result_sources.py`, `api/settings.py` (Wave 3-C 경로 안정화)
     - `analyzer/file_io.py`, `analyzer/static_tool_command_runner.py`, `analyzer/command_env.py` (Wave 3 / 4 어댑터)
     - `shared/command_env.py` (Wave 4-J 이후 boundary 중립화)
     - `validator/file_io.py`, `validator/validator_command_runner.py` (Wave 4-O 어댑터)
     - Wave 2 ~ Wave 4-Z 의 회귀 테스트 다수
3. **Gusle01 의 코드는 “리팩토링 이전 모놀리스” 위에서 작성됐다.**
   - `api/server.py` 가 1,152 줄에서 라우터/서비스/DTO/Settings 로 분해된 것이 Dallo_v2 의 클린 아키텍처 자산인데, gusle01 은 그 분해가 일어나기 전 시점의 server.py 에 Red/Blue 기능을 인라인으로 추가했다.
   - 따라서 gusle01 의 변경 라인을 그대로 가져오면 책임 분리와 seam 이 무너진다.
4. **결론**: 직접 머지/체리픽 금지. Gusle01 에서 가져오는 것은 **"기능 의도"** 뿐이며, 구현은 Dallo_v2 의 라우터/서비스/도메인/어댑터/seam 위에서 **다시 쓴다(backport-by-rewrite)**.

---

## 5. 기능 분류 표 (Feature Classification)

용어:

- **Adopt**: 의도와 형태 모두 Dallo_v2 위에서 다시 구현해 가져온다.
- **Rewrite**: 의도는 가져오되 구조는 Dallo_v2 seam 위에서 새로 쓴다 (코드 직접 복사 금지).
- **Defer**: 본 wave 시리즈에서는 보류. 별도 wave + 사용자 승인 필요.
- **Reject**: 사용자 정책 / 보안 / 아키텍처 이유로 거부. 다시 채택하지 않는다.
- **Already present**: Dallo_v2 에 이미 같은 기능이 있다. 추가 작업 불필요.

| # | 기능 의도 (Feature intent) | Gusle01 증거 (파일 / 함수) | Dallo_v2 목표 위치 | 결정 (Decision) | 필요한 검증 (Verification) |
|---|---|---|---|---|---|
| 1 | Red/Blue 도메인 enrichment (취약점/패치 dict 에 공격/방어 컨텍스트 파생 부착) | `shared/red_blue.py` (`enrich_vulnerability`, `enrich_patch`, `build_red_blue_summary`, `build_attack_paths`, `build_defense_comparison`) | `shared/red_blue.py` 신규 (순수 함수 모듈) | **Rewrite** | `tests/test_shared_red_blue.py` 신규 — CWE 템플릿 매트릭스, defense outcome 4 케이스, deepcopy 안전성, comparison 산수 (Wave 5-B). |
| 2 | `/api/red-blue/summary` 엔드포인트 (DB→JSON→empty 3단 폴백) | `api/server.py:625-647` `get_red_blue_summary` | 신규 `api/routers/red_blue.py` + 신규 `api/services/red_blue_summary.py`, `api/server.py` 에 `include_router` 한 줄만 추가 | **Rewrite** | `tests/test_api_red_blue_router.py` 신규 — 401 / 200 / JSON 손상 폴백 (Wave 5-C). |
| 3 | 대시보드 쿼리 응답에 Red/Blue 키 자동 부착 | `api/server.py:414-470` `_with_red_blue` | `api/services/red_blue_view.py` 또는 `api/services/dashboard_queries.py` 의 끝단 enrichment | **Rewrite** (additive only, 기존 키 불변) | `tests/test_api_dashboard_red_blue_passthrough.py` — `_Permissive(extra="allow")` + `response_model_exclude_unset=True` 동작 확인 (Wave 5-D). |
| 4 | 프론트엔드 RedBlueView / 탭 / Analyze 카드 / Patch / Report UI | `dashboard/src/components/RedBlueView.jsx`, `App.jsx` redblue tab, `AnalyzeView.jsx`, `PatchView.jsx`, `ReportView.jsx` | `dashboard/src/components/RedBlueView.jsx` 신규 + 기존 컴포넌트에 섹션 추가 | **Defer** (backend contract 확정 후, 별도 frontend wave 5-I) | `npm run build` 통과 + 수동 라우트 200 확인 + gateway selector 제거 확인. |
| 5 | 리포트 Red/Blue 섹션 (HTML 리포트에 공격/방어 블록 표시) | `reports/report_generator.py` (gusle01 add/add 충돌 본) | 기존 `reports/report_generator.py` 에 섹션만 추가 (전체 파일 교체 금지) | **Rewrite** (섹션만, escaping/안전 파일명 보존) | `tests/test_report_generator.py` 확장 — HTML escape 회귀 + 신규 섹션 렌더링 (Wave 5-J). |
| 6 | LLM 대상 최적화 (`cve_scope` / `cwe_scope` / `rule_scope` / `max_llm_targets` / `max_context_chars`) | `shared/llm_optimization.py`, `analyzer/pipeline.py` 옵션, `config/config.yaml` `llm.optimization`, `AnalyzeView.jsx` | `shared/llm_optimization.py` 신규 (순수 모듈) + `analyzer/pipeline.execute_pipeline` 의 `*, clock=None, file_io=None` 뒤로 keyword-only 옵션 추가 + `api/routers/analyze.py::AnalyzeRequest` / `api/services/analysis_pipeline.execute_analysis_job` / `api/tasks.py::run_analysis_task` 옵션 전달 | **Rewrite** (Gemini 디폴트 보존) | `tests/test_shared_llm_optimization.py` 신규 + `tests/test_pipeline_integration.py` 옵션 회귀 + fake provider (Wave 5-E + 5-F). |
| 7 | 같은 파일 묶음 batch LLM 패치 (LLM 호출 비용 감소) | `agent/llm_agent.py::generate_patches_batch` | 기존 `DalloAgent.generate_patches(..., batch=False, batch_size=5)` 시그니처 확장. Wave 4-M 의 `sleeper` seam 보존 | **Rewrite** (5-G) | fake provider 테스트로 group_by_file/build_batch_prompt/parse_batch_response 회귀 (`agent/batch_processor.py` 는 이미 존재). |
| 8 | 정적 스캔이 비었을 때 LLM 보조 감사 (clean-scan LLM audit) | `agent/llm_agent.py::audit_code`, `analyzer/pipeline.py::_generate_clean_audit`, UI `llm_audit_when_clean` | `DalloAgent.audit_code` 신규 + `analyzer/pipeline.py` 의 옵트인 분기. 디폴트 `False`, Gemini 유지 | **Rewrite** (5-G, 옵트인) | fake provider 테스트 + LLM 호출 0 검증 + 결과 dict 의 `llm_audit` 부착 형태 검증. |
| 9 | Heuristic fallback 정적 분석기 (SQLi / cmd injection / hardcoded secret / weak hash / CWE-288 auth bypass) | `analyzer/heuristic_runner.py`, `analyzer/semgrep_runner.py::detect_and_run` | 기존 `analyzer/quick_scan.py` 의 정규식 규칙 자산을 기반으로 한 **공유 순수 line-scanning helper**. `os.walk/open` 직접 호출 금지, `FileIO` 어댑터 경유 | **Rewrite** (5-H) | fake `FileIO` + fake `StaticToolCommandRunner` 기반 단위 테스트. CWE-288 full-scan 분기 신규 회귀 가드. |
| 10 | Java SSRF 등 커스텀 Semgrep 룰 | `config/semgrep/custom-java-security.yml` (gusle01 신규) | 로컬 `config/semgrep/` 디렉터리 신설 + 같은 YAML 파일 도입 | **Adopt** (룰 YAML 자체는 그대로 사용 가능, 코드 아님) | `tests/test_semgrep_runner.py` 확장 — 멀티 config 입력이 `StaticToolCommandRunner` argv 에 정상 들어가는지 fake 로 검증 (Wave 5-H 동반). |
| 11 | Semgrep multi-config (여러 룰셋 병합 실행) | `analyzer/semgrep_runner.py` gusle01 변경분 | 기존 `analyzer/semgrep_runner.py` 의 argv 빌더에 다중 `-c` 옵션 추가. 외부 레지스트리 자동 다운로드는 금지 | **Rewrite** (5-H, 로컬 YAML 한정) | fake runner 단위 테스트. 외부 네트워크 호출 0 검증. |
| 12 | Quick scan auth-bypass 룰의 `require_all` 매칭 정책 | `analyzer/heuristic_runner.py` 의 CWE-288 매칭 + `quick_scan` 룰 확장 | 기존 `analyzer/quick_scan.py` 의 정규식 규칙 메타데이터에 `require_all` 정책 도입 | **Rewrite** (5-H 안의 작은 sub-wave) | 신규 테스트 — 단일 라인 매칭으로는 트리거 안 되고, 두 라인이 동시에 있을 때만 finding 이 나오는지. |
| 13 | Bandit `shutil.which` / `python -m bandit` 폴백 | gusle01 `analyzer/bandit_runner.py` 변경분 | 기존 `analyzer/bandit_runner.py` 의 한국어 에러 메시지(`"Bandit이 설치되어 있지 않습니다"`) 와 `StaticToolCommandRunner` argv 정책은 보존하면서, 폴백 argv 만 어댑터 안에서 결정 | **Defer** (5-H 와 별도, 운영 영향이 작아 우선순위 낮음) | fake runner — `bandit` 미존재 시 `python -m bandit` argv 가 만들어지는지 회귀. |
| 14 | DB `DATABASE_URL` 빈 문자열 폴백 (`""` 도 `_SQLITE_URL` 로 떨어짐) | gusle01 `db/models.py` 변경분 | **이미 존재** — 로컬 `db/models.py:50` 에 `DATABASE_URL = os.environ.get("DATABASE_URL") or _SQLITE_URL` 이 적용되어 있음 | **Already present** | 추가 작업 없음. 단, 회귀 가드 테스트 추가 여부는 5-A 외부에서 결정. |
| 15 | `start.py` 의 명시적 `.env` 로딩 | gusle01 `start.py` 변경분 | 로컬 `start.py` 는 현재 dotenv 를 호출하지 않음. 의도가 유용하지만 `start.py` 는 운영 부트스트랩이라 영향 범위가 큼 | **Defer** (별도 승인 후 5-K 정도로 가능) | 부트스트랩 회귀 — `.env` 없을 때 동작 보존, 있을 때 변수 우선순위 충돌 없음. |
| 16 | `gateway_provider` / `LLM_PRIMARY_PROVIDER=gateway` / `provider="gateway"` / `model="claude-sonnet-4-6"` 기본값 | `agent/providers/gateway_provider.py`, `agent/provider_factory.py` 게이트웨이 활성화, `.env.example`, `api/server.py:81` 기본값, 프론트엔드 provider selector | (해당 없음 — 채택하지 않음) | **Reject** (정책 위반) | 회귀 가드: grep 가드 + AST 가드로 `"gateway"`, `"claude-sonnet-4-6"`, `LLM_PRIMARY_PROVIDER=gateway` 토큰이 `main` 으로 다시 들어오지 못하게 한다. |
| 17 | `shared/schemas.py` 에 Red/Blue 필드 추가 + `AnalysisSession.to_dict()` 부수효과 | gusle01 `shared/schemas.py` (+24 라인) | (해당 없음 — `shared/schemas.py` 무변경) | **Reject (default)** / **Defer with explicit approval** | 만일 추후 dataclass 필드가 정말 필요하면 그때 별도 wave + 사용자 명시 승인 + DB 마이그레이션/직렬화 회귀 테스트가 모두 필요. |
| 18 | `update.me` / `README.md` / `CLAUDE.md` 의 Gusle01 문서 변경 | gusle01 add/add 충돌 (`update.me`), README, CLAUDE.md | 본 wave 에서는 가져오지 않음. Dallo_v2 의 wave 이력은 `docs/refactoring/clean-architecture-wave-history.md` 가 단일 권위 | **Defer** (필요 시 별도 docs wave) | 없음. |

---

## 6. 명시 거부 / 보류 — 게이트웨이 / claude-sonnet 기본값

본 절은 §5 의 #16 / #17 결정을 **다시 한 번 명시** 한다.

### 6-1. Hard Reject (현재 정책상 채택 금지)

다음 항목은 사용자가 “Gemini / Google AI Studio 를 기본 LLM 경로로 유지” 라고 명시했기 때문에, **별도 정책 변경 승인이 없는 한** 채택하지 않는다.

- `agent/providers/gateway_provider.py` (모듈 자체의 도입).
- `agent/provider_factory.py` 의 게이트웨이 활성화 (`_ACTIVE_PROVIDERS` 에 `"gateway"` 추가, `PRIMARY_PROVIDER` 기본값을 `"gateway"` 로 전환).
- `.env.example` 의 `LLM_PRIMARY_PROVIDER=gateway`.
- `api/server.py` (현 라우터 분리 후에는 `api/routers/analyze.py`) 의 `provider="gateway"` / `model="claude-sonnet-4-6"` 기본값.
- 프론트엔드 provider selector 의 기본 항목이 gateway 인 형태.

이유:

- 사용자가 명시한 LLM 기본 경로는 **Google AI Studio / Gemini** 다.
- gateway 경로는 추가적인 외부 라우팅/요금/보안 위험을 가지며, 현재 Dallo_v2 의 fake-provider 테스트 매트릭스 밖에 있다.
- claude-sonnet-4-6 같은 특정 모델 디폴트는 사용자/조직의 모델 선택 자율성을 박탈한다.

회귀 차단 방안 (향후 wave 에서 가드 적용):

- grep 가드: 운영 코드(`agent/`, `api/`, `.env.example`, `config/config.yaml`, `dashboard/src/`) 에 토큰 `"gateway"`, `"claude-sonnet-4-6"`, `LLM_PRIMARY_PROVIDER=gateway` 가 디폴트로 도입되는 변경이 PR 라인에 나타나면 차단.
- AST 가드: `AnalyzeRequest` 의 디폴트 값이 `"gateway"` 또는 `"claude-sonnet-4-6"` 로 바뀌면 차단.
- 테스트 가드: `tests/test_api_analyze_router.py` 의 `provider="gemini" / model="gemini-2.0-flash-lite"` 디폴트 회귀 테스트 유지.

### 6-2. Defer (현 시점 보류, 별도 wave 에서 결정)

- `shared/schemas.py` 의 Red/Blue 필드 추가. (스키마는 시스템 계약이며 DB/직렬화/테스트 골든에 광범위한 파급을 갖는다.)
- 분석 스코프 플래그 (`cve_scope` / `cwe_scope` / `rule_scope` / `max_llm_targets` / `max_context_chars` / `batch_llm` / `llm_audit_when_clean`) 전체 패키지를 한 번에 도입하는 것. → 5-E + 5-F 로 잘라서 진행.
- `start.py` 의 명시적 `.env` 로딩 도입.
- `update.me` / README / CLAUDE.md 의 Gusle01 문서 본문을 그대로 가져오는 것.

---

## 7. Dallo_v2 매핑 — 레이어별 배치 (Layered Mapping)

본 절은 Wave 5-B 이후의 코드 wave 가 “어느 레이어에 무엇을 둘 것인가” 를 미리 합의해 둔다.
`api.services` 가 FastAPI/Pydantic 비의존을 유지하고, 라우터는 얇게, 도메인은 순수 함수로 둔다는 Dallo_v2 의 원칙을 따른다.

### 7-1. `shared/` 와 도메인 (domain)

- **`shared/red_blue.py` (신규)** — 순수 함수 모듈. 입력은 dict, 출력은 dict. FastAPI / DB / settings / time / file system 의존 0.
  - `enrich_vulnerability(vuln_dict) -> dict`
  - `enrich_patch(patch_dict, vuln_dict | None) -> dict`
  - `build_red_blue_summary(vulns, patches) -> dict`
  - `build_attack_paths(vulns) -> list[dict]`
  - `build_defense_comparison(vulns, patches) -> dict`
- **`shared/llm_optimization.py` (신규, 5-E)** — 순수 모듈. `cve_scope` / `cwe_scope` / `rule_scope` / `max_llm_targets` / `max_context_chars` 의 정책 결정을 입력 dict 만으로 수행. 외부 의존 0.
- **`shared/schemas.py`** — **본 wave 와 향후 Red/Blue wave 시리즈에서 변경하지 않음.** 변경이 필요해지면 별도 사용자 승인.

### 7-2. `analyzer/` 와 agent (analysis pipeline)

- `analyzer/pipeline.py::execute_pipeline` — 기존 `*, clock=None, file_io=None` seam 뒤로 다음 keyword-only 옵션을 추가 (5-F 에서). 디폴트는 기존 동작과 동일.
  - `cve_scope`, `cwe_scope`, `rule_scope`, `max_llm_targets`, `max_context_chars`, `batch_llm`, `llm_audit_when_clean`
- `analyzer/quick_scan.py` — 5-H 에서 CWE-288 auth-bypass 의 `require_all` 정책 도입. 기존 정규식 규칙 메타데이터에 모드 키만 추가.
- `analyzer/heuristic_runner.py` — gusle01 모듈의 의도(SQLi / cmd injection / hardcoded secret / weak hash / CWE-288 full-scan) 만 가져오되 **`os.walk` / `open` 직접 호출 금지**. 모든 디스크 접근은 `FileIO` 어댑터 경유. 5-H 에서 결정.
- `analyzer/semgrep_runner.py` — 5-H 에서 multi-config 입력 지원 추가. 원격 레지스트리 자동 다운로드는 금지. `StaticToolCommandRunner` argv 어댑터 + child env sanitizer 보존.
- `analyzer/bandit_runner.py` — 5-H 와 별도, defer. 폴백 argv 결정은 어댑터 안에 격리.
- `agent/llm_agent.py` — 5-G 에서 다음 두 변경:
  - `generate_patches(..., batch=False, batch_size=5)` 시그니처 확장. Wave 4-M `sleeper` seam 보존.
  - `audit_code(...)` 신규 메서드. fake provider 테스트로만 검증. Gemini 디폴트 유지.

### 7-3. `api/` (service / router / dto)

- **router**
  - `api/routers/red_blue.py` (신규, 5-C) — `GET /api/red-blue/summary`, `Depends(verify_api_key)`. 본문은 서비스 호출 + DTO 변환.
  - `api/routers/analyze.py` — 5-F 에서 `AnalyzeRequest` 에 7 개 옵션 필드 추가. 디폴트는 *현재 동작 보존* — 즉 옵션 미지정 시 동작 무변경.
  - `api/server.py` — 5-C 에서 `app.include_router(red_blue.router)` 한 줄만 추가. 모놀리스 회귀 금지.
- **service**
  - `api/services/red_blue_summary.py` (신규, 5-C) — DB → JSON → empty-shape 3 단 폴백. `api.result_sources` 와 `db.service` 만 의존. FastAPI 비의존.
  - `api/services/red_blue_view.py` (신규, 5-D) — `dashboard_queries.get_*` 결과에 `shared.red_blue.enrich_*` 적용. 라우터 호출은 그대로.
  - `api/services/result_normalizers.py` (옵션, 5-C 와 함께 또는 별도) — 구버전 `full_result.json` 의 `llm_audit.findings` 를 응답 `vulnerabilities` 에 동화하는 어댑터. 사용 여부는 사용자 승인 후 결정.
  - `api/services/dashboard_queries.py` — 5-D 에서 `get_vulnerabilities` / `get_patches` / `get_stats` / `get_session_detail` 끝단에 `red_blue_view.enrich_*` 호출. 키는 *추가만* (additive).
  - `api/services/analysis_pipeline.py::execute_analysis_job` — 5-F 에서 새 옵션 dict 전달.
  - `api/tasks.py::run_analysis_task` — 5-F 에서 Celery task 시그니처에 새 옵션 dict 전달.
- **dto**
  - `api/dto/responses.py` — 5-D 에서 `VulnerabilityItem` / `PatchItem` 에 Optional Red/Blue 필드 추가, 신규 `RedBlueSummaryResponse` 추가. `_Permissive(extra="allow")` + `response_model_exclude_unset=True` 가 이미 추가 키를 허용하므로 기존 응답 회귀 없음.

### 7-4. `dashboard/` (프론트엔드)

- `dashboard/src/components/RedBlueView.jsx` (신규, 5-I) — Red Team 발견 / Blue Team 조치 / attack paths / residual risk 표시.
- `dashboard/src/App.jsx` — redblue 탭 추가.
- `dashboard/src/components/AnalyzeView.jsx` — Red/Blue 요약 카드 + LLM 최적화/clean audit 표시 (5-I 와 동반).
- `dashboard/src/components/PatchView.jsx` — Blue Team wording 보정 (5-I).
- `dashboard/src/components/ReportView.jsx` — Red/Blue 섹션 표시 (5-J 와 동반).
- 모든 프론트엔드 wave 는 **backend contract 확정 후** 시작한다.
- **gateway provider selector 가 기본인 형태는 채택 금지** — gusle01 의 UI 변경 중 LLM provider 디폴트 변경 부분은 5-I 에서 명시적으로 제외한다.

### 7-5. `reports/` 와 `docs/`

- `reports/report_generator.py` — 5-J 에서 Red/Blue 섹션만 추가. 기존 HTML escaping, 안전 파일명, dependency 섹션, 기타 보안 속성은 그대로 보존. **전체 파일 교체 금지.**
- `docs/refactoring/clean-architecture-wave-history.md` — 매 wave 의 머지 후 sync 항목 추가. 본 wave 도 5-A 짧은 항목을 (선택적으로) 덧붙인다.

### 7-6. `tests/` 와 검증

- 각 wave 는 신규 fake-seam 단위 테스트 + 기존 회귀 가드(`tests/test_api_contract.py` / `tests/test_api_dashboard_queries_service.py` / `tests/test_api_analyze_router.py` / `tests/test_api_server_syspath.py` / `tests/test_api_lifespan.py` / `tests/test_api_server.py` / `tests/test_api_result_sources.py`) **모두** 통과해야 한다.
- 실 LLM / 실 GitHub / 실 Bandit / 실 Semgrep / 실 Sonar / 실 Redis / 실 pip-audit / 실 npm 호출 0 건이 모든 wave 의 기본값이다.

---

## 8. 권장 후속 wave 순서 (5-A 이후) — 매 wave 사용자 승인 필요

각 wave 는 작은 범위 + revertable 단일 머지 커밋 + fake-seam 테스트를 기본 단위로 갖는다.
화살표(→) 는 의존 관계다. 의존 관계가 없는 wave 도 합의된 순서를 따른다.

| Wave | 이름 | 범위 (한 줄) | 사용자 승인 게이트 |
|---|---|---|---|
| **5-A** | Red/Blue 백포트 선별 (본 문서) | 본 wave. 문서만. | 시작 시점에 “Wave 5-A 실행” 승인 받음. 완료 후 5-B 진행 여부 재승인. |
| **5-B** | Red/Blue 순수 도메인/서비스 | `shared/red_blue.py` 신규 + 단위 테스트. **API 노출 없음.** | 5-B 의 함수 시그니처와 출력 dict 키 셋 명시 승인. |
| **5-C** | `/api/red-blue/summary` 라우터/서비스 | 신규 `api/routers/red_blue.py` + `api/services/red_blue_summary.py` + DTO 추가. server.py 에 `include_router` 한 줄. | 새 엔드포인트 활성화 + 인증 정책 (`verify_api_key`) 승인. |
| **5-D** | 대시보드 쿼리 응답 enrichment | `api/services/dashboard_queries.py` 끝단 + `api/services/red_blue_view.py` + DTO 의 Optional 필드. | 기존 4 개 엔드포인트 응답에 *추가 키* 부착 정책 승인 (additive only). |
| **5-E** | `shared/llm_optimization.py` 순수 모듈 | 신규 모듈 + 단위 테스트. **호출 없음.** | 정책 함수 시그니처/디폴트 승인. Gemini 기본값 보존 재확인. |
| **5-F** | 파이프라인 / API / Celery 옵션 plumbing | `analyzer/pipeline.execute_pipeline` keyword-only 옵션 + `api/routers/analyze.py::AnalyzeRequest` 옵션 + `api/services/analysis_pipeline.execute_analysis_job` + `api/tasks.py::run_analysis_task`. | 새 옵션 7 개 활성화 + 디폴트가 기존 동작과 동일함을 회귀 테스트로 증명. |
| **5-G** | Agent batch generation + clean audit (옵트인) | `DalloAgent.generate_patches(..., batch=, batch_size=)` + `DalloAgent.audit_code(...)`. fake provider 테스트. | 옵트인 정책 + 디폴트 `False` + Gemini 모델 디폴트 보존 승인. |
| **5-H** | Heuristic fallback + Semgrep 커스텀 룰 + multi-config | `analyzer/quick_scan.py` `require_all` 정책 + 공유 heuristic 헬퍼 + `config/semgrep/custom-java-security.yml` + `analyzer/semgrep_runner.py` multi-config. | 새 룰 활성화, multi-config 정책, **외부 레지스트리 자동 다운로드 금지** 정책 승인. |
| **5-I** | 프론트엔드 RedBlueView + 카드/탭 | `dashboard/src/components/RedBlueView.jsx` 신규 + `App.jsx` 탭 + Analyze/Patch 카드. gateway selector 미도입. | `npm run build` 통과 + 수동 라우트 200 확인 + 문구 (한국어) 승인. |
| **5-J** | 리포트 Red/Blue 섹션 + 문서 sync | `reports/report_generator.py` 섹션 추가 + `docs/refactoring/clean-architecture-wave-history.md` sync. | HTML escaping 회귀 가드 + 신규 섹션 wording 승인. |

각 wave 의 종료 조건: **(a) 신규 fake-seam 테스트 그린, (b) full `pytest tests/ -q` 그린, (c) 기존 회귀 가드 그린, (d) 보안 grep / AST 가드 그린, (e) 머지 커밋 1 개로 revertable.**

---

## 9. 검증 매트릭스 (Verification Matrix)

각 후속 wave 가 통과해야 할 검증의 표준 매트릭스. 본 wave (5-A) 는 문서 전용이므로 본 매트릭스를 *적용하지 않고*, 5-B 이후 wave 부터 적용한다.

| 검증 항목 | 적용 wave | 도구 / 방법 | 합격 기준 |
|---|---|---|---|
| Targeted 단위 테스트 | 5-B ~ 5-J | `pytest <new_test_file>.py -q` | 신규 회귀 모두 green |
| Full pytest | 5-B ~ 5-J | `pytest tests/ -q` | 851+ passed (현 baseline 851 + 신규 회귀 수) |
| API TestClient smoke | 5-C / 5-D / 5-F | FastAPI `TestClient`, fake DB / fake services | 모든 변경된 라우터 200 + 응답 셰이프 검증 |
| Fake provider 강제 | 5-E / 5-F / 5-G | `agent.provider_factory.get_provider` 모킹 또는 fake provider 주입 | 실 LLM 호출 0 (네트워크 traffic 0) |
| Fake command runner 강제 | 5-H | `StaticToolCommandRunner` / `DependencyCommandRunner` fake 주입 | 실 Semgrep / Bandit / pip-audit / npm 호출 0 |
| Fake FileIO 강제 | 5-H | `analyzer.file_io.FileIO` fake 주입 | 실 disk 쓰기 0 (임시 파일 잔류 0) |
| Fake clock 강제 | 5-F / 5-G | `analyzer.pipeline.execute_pipeline(clock=...)`, `LLMCache(clock=...)`, agent `sleeper=...` | 실 `time.time()` / `time.sleep()` 호출 0 |
| Frontend npm build | 5-I | `cd dashboard && npm run build` | exit 0 |
| 보안 grep 가드 | 모든 wave | `git diff --unified=0` 의 추가 라인에 secret-like 리터럴 / `os.system(` / `shell=True` / `eval(` / `exec(` / `pickle.loads?(` 검출 | 추가 라인 0 |
| 정책 grep 가드 | 모든 wave | 추가 라인에 `"gateway"` / `"claude-sonnet-4-6"` / `LLM_PRIMARY_PROVIDER=gateway` / `sys.path.insert` / 모듈 최상위 `init_db()` 검출 | 추가 라인 0 |
| RED-first 증명 | 5-B ~ 5-J | 본 wave 의 신규 테스트를 baseline (구현 미적용) 에서 먼저 실행 | 합당한 항목이 정확히 fail (회귀 가드의 유효성 증명) |
| Independent read-only 리뷰 | 코드 변경 wave 전체 | 별도 read-only 리뷰어 인스턴스 | `VERDICT: APPROVED` |

---

## 10. 승인 게이트 (Approval Gates)

본 wave 시리즈 전반에서, 다음 결정은 사용자 명시 승인이 없는 한 코드에 들어가지 않는다.

1. **`shared/schemas.py` 의 변경** — 어떤 dataclass 필드 추가/제거든 모두 명시 승인. Red/Blue 필드를 dataclass 에 박는 결정은 본 wave 시리즈 기본값에서 **거부** 되어 있다.
2. **새 API 엔드포인트의 활성화** — 본 문서가 계획한 것을 넘어선 새 엔드포인트 (예: `/api/red-blue/...` 외 추가 URL) 는 별도 승인.
3. **gateway provider 의 도입/활성화** — `agent/providers/gateway_provider.py` 의 도입, `provider_factory` 의 활성화, AnalyzeRequest 의 디폴트 변경 모두 별도 정책 승인 사안.
4. **실 외부 호출의 도입** — 실 Gemini / 실 GitHub / 실 Sonar / 실 Bandit / 실 Semgrep / 실 pip-audit / 실 npm 호출이 단위 테스트 또는 CI 에서 발생하는 변경은 별도 승인. 본 wave 시리즈의 기본값은 fake-seam only.
5. **프론트엔드의 “제품 문구(product wording)” 변경** — Red/Blue 카드 한국어 문구, 탭 이름, 사용자 메시지 한국어 wording 결정은 사용자 명시 승인.
6. **`analysis_mode = "red_blue"` 같은 응답 최상위 마커 키** — 응답 contract 의 최상위 키 추가는 명시 승인.
7. **분석 스코프 플래그 (5-F)** — 7 개 옵션 (`cve_scope` / `cwe_scope` / `rule_scope` / `max_llm_targets` / `max_context_chars` / `batch_llm` / `llm_audit_when_clean`) 의 전부/일부 활성화는 별도 승인.
8. **`shared/red_blue.py` 의 최종 경로** — 후보: `shared/red_blue.py` (gusle01 평행) vs `analyzer/red_blue.py` (분석 도메인) vs `api/services/red_blue_view.py` 단독 (FastAPI 전용 표면). 현재 권장은 `shared/red_blue.py` + `api/services/red_blue_view.py` 호출. 5-B 시작 전에 사용자 명시 승인 필요.

---

## 11. 최종 결론

- **방법**: backport-by-rewrite. 직접 머지/체리픽 금지.
- **기준**: Dallo_v2 `main` 의 라우터/서비스/도메인/어댑터/seam 위에서 다시 구현.
- **LLM 기본 경로**: Google AI Studio / Gemini 유지. gateway / claude-sonnet-4-6 디폴트 거부.
- **스키마**: `shared/schemas.py` 무변경 (별도 승인 시에만 변경).
- **순서**: 5-B → 5-J 까지의 작은 wave 시퀀스, 매 wave 사용자 승인 + fake-seam 테스트 + revertable 머지.
- **본 wave (5-A)**: 문서만. 운영 코드/테스트/스키마/패키지/설정 어떤 것도 변경 없음. 머지/푸시/PR/배포/실 외부 호출 어떤 것도 수행 없음.

— Wave 5-A 종료.
