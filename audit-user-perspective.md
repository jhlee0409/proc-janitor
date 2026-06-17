# proc-janitor — 실사용자 관점 분석 리포트

> 작성: 2026-06-17 · 대상 버전 0.8.1 · 방법: 핵심 모듈 직접 정독(scanner/kill/cleaner/config/daemon/session/util/README/systemd·launchd 리소스) + 10개 렌즈 멀티에이전트 감사(44 에이전트, 원시 발견 73건 → 적대적 검증 후 confirmed 16 / partial 15 / 반증 3)

---

## 0. 총평

**저수준 안전장치는 진짜로 탄탄하다.** 시스템 PID 가드(0/1/2), `start_time` 기반 PID 재사용 신원검증, `fs2` 파일락(세션 RMW 전체에 배타락), `O_NOFOLLOW` 심볼릭링크 보호, 손상 JSON 백업·복구, 권한 0o700 — 이미 여러 차례 보안 리뷰를 거친 흔적이 코드에 뚜렷하다.

**문제는 거의 전부 "정책 / 기본값 / 배포 / UX" 레이어에 있다.** 즉 "프로세스를 죽이는 메커니즘"이 아니라 **"무엇을 죽일지 정하는 정책"과 "어떻게 설치·구동되는지"**에서 사용자가 다친다. 적대적 검증 결과, "self/부모 셸을 죽인다", "macOS 재부모화가 안 돼 못 잡는다", "Apple Silicon plist 경로 깨짐" 같은 자극적 주장 3건은 **반증**되었다(아래 §6 참고). 남은 실재 이슈는 아래와 같다.

### 최우선 수정 6선 (실사용자가 실제로 다치는 순서)

| # | 이슈 | 파일 | 등급 | 검증 |
|---|------|------|------|------|
| 1 | `reload` 명령이 설정 리로드가 아니라 **데몬을 종료**시킴 | `src/daemon.rs` | 치명 | confirmed |
| 2 | 설정 파일이 없어도 **기본 타깃이 활성** → 첫 실행이 Claude/MCP 즉사 | `src/config.rs` | 치명 | confirmed |
| 3 | `session auto-clean`이 **살아있는 세션의 프로세스를 죽임** | `src/session.rs` | 치명 | confirmed |
| 4 | `dev` 프리셋 + **무앵커 부분일치**로 사용자 본인 node/python 오살 | `src/config.rs`·`scanner.rs` | 치명 | confirmed |
| 5 | 기본 `clean`이 **무확인·즉시 SIGKILL**, dry-run 플래그 없음 | `src/cleaner.rs`·`cli.rs` | 높음 | partial |
| 6 | **Linux 배포가 통째로 깨짐**(ExecStart 경로 불일치 + linger 없음 + ProtectHome) | `resources/`·`README.md` | 높음 | confirmed |

---

## 3. 치명적인 이슈 (Critical) — 먼저

### C-1. `proc-janitor reload`가 데몬을 죽인다 ★최우선
- **위치**: `src/daemon.rs:115-128`(시그널 핸들러), `daemon.rs:642`(reload→SIGHUP), `Cargo.toml:50`
- **사실**: `ctrlc = { features = ["termination"] }`. ctrlc의 termination 기능은 등록한 단일 핸들러를 **SIGINT·SIGTERM·SIGHUP 모두**에 대해 호출한다. 그 핸들러는 `running.store(false)` 즉 종료 로직이다. 그런데 `reload()`는 데몬에 **SIGHUP**을 보낸다 → 데몬은 설정을 다시 읽는 게 아니라 **종료된다**. 게다가 `daemon.rs:645`는 "Config will be reloaded on next scan cycle"라는 **거짓 메시지**까지 출력한다.
- **은폐되는 이유**: launchd(`KeepAlive=true`)는 죽은 데몬을 자동 재시작해 "리로드된 척" 보인다. 하지만 **systemd(`Restart=on-failure`)는 SIGHUP에 의한 정상종료(exit 0)를 실패로 보지 않아 재시작하지 않는다** → 데몬이 멈춘 채 방치되고, 그 순간부터 고아 청소가 전혀 안 된다.
- **수정**: SIGHUP을 종료와 분리. `signal-hook`으로 SIGINT/SIGTERM→종료 플래그, SIGHUP→reload 플래그로 라우팅하고 메인 루프에서 `check_config_reload()` 호출. 임시방편으로는 이미 mtime 자동 리로드(`daemon.rs:66`)가 동작하므로 `reload` 명령을 제거하고 "설정은 다음 스캔 주기에 자동 반영"으로 안내만 해도 피해는 막힌다. **반드시 통합 테스트로 reload 후 데몬 생존을 검증할 것.**

### C-2. 설정 파일이 없어도 기본 타깃이 활성 → 첫 실행이 위험
- **위치**: `src/config.rs:58-82`(`new_default`), `config.rs:160-163`(`load_from_file`)
- **사실**: config 파일이 없으면 `Config::load()`가 **빈 설정이 아니라** `new_default()`를 반환하고, 그 targets는 `["node.*claude","claude","node.*mcp"]`로 비어있지 않다. `clean`/`start` 진입부에 "config 존재" 게이트가 없다.
- **사용자 영향**: Claude Code를 실제로 쓰는 개발자가 `brew install` 직후 호기심에 `proc-janitor clean`을 치면 — 본인이 단 한 줄도 설정하지 않았는데 — **현재 작업 중인 Claude Code 세션·MCP 서버가 즉사**한다. 진행 중 대화/작업 유실.
- **수정**: config 파일이 실제로 없을 때는 `targets=[]`(no-op)로 동작시키고, `clean`/`start`는 "config init을 먼저 실행하세요"로 거부. "안전한 기본값 = 아무것도 안 함" 원칙. 최소한 `load()`에 `from_file: bool`을 두어 첫 실행 시 강제 확인.

### C-3. `session auto-clean`이 살아있는 세션을 죽인다
- **위치**: `src/session.rs:309`(register 기본 parent_pid), `session.rs:503-570`(auto_clean)
- **사실 두 겹**:
  1. `register()`는 `--parent-pid` 미지정 시 `parent_pid = std::process::id()` 즉 **`session register` CLI 자신의 PID**를 저장한다. 이 CLI는 등록 직후 종료한다.
  2. `auto_clean()`은 `parent_pid`가 프로세스 테이블에 없으면 세션을 stale로 보고 **`session.pids`의 descendant 트리 전체**를 죽인다.
- **결과**: 등록 CLI는 이미 죽었으므로 **모든 기본 등록 세션이 등록 직후부터 영구히 stale**. 터미널·Claude Code가 멀쩡히 살아 있어도 `auto-clean` 한 번에 추적 프로세스(빌드/개발서버 등)가 전부 죽는다. README 예시(`session register --source claude-code`)가 정확히 이 함정에 빠진다.
- **수정**: 기본 parent_pid를 `nix::unistd::getppid()`(부모 터미널/Claude)로. `parent_start_time`도 함께 저장해 auto_clean에서 PID 존재 + start_time 일치를 모두 확인(PID 재사용 방어). stale 정의를 "(a) 부모 죽음 **그리고** (b) 추적 PID도 죽거나 PPID=1 고아화"로 강화.

### C-4. `dev` 프리셋 + 무앵커 부분일치로 사용자 본인 프로세스 오살
- **위치**: `src/config.rs:385-388`(`dev` 프리셋), `scanner.rs:195-197`(`matches_target`), `scanner.rs:208-215`(`get_cmdline`)
- **사실**: `matches_target`는 `^`/`$` 앵커 없이 **전체 cmdline(모든 argv를 공백 join)**에 `is_match`를 돌린다. `dev` 프리셋 targets는 `["node","cargo","python","webpack|vite|esbuild"]`. 즉 `python`은 인자에 `/usr/bin/python`만 있어도, `node`는 경로에 `node`가 있는 무엇(전자 앱, nodemon, `.../node_modules/...`)이든 매칭된다. `dev` whitelist는 `["node.*server","pm2","node.*next"]`뿐이라 **cargo·python은 보호가 전혀 없다.**
- **PPID=1 전제 입증**: 실측 결과 이 머신에 사용자 소유 PPID=1 프로세스가 수백 개 존재(launchd가 직접 띄운 LaunchAgent·`brew services` 데몬 포함). 즉 사용자가 정상 등록한 백그라운드 python/node 서버도 1차 필터(PPID=1)를 통과한다. 터미널을 닫아 부모가 죽으면 일반 작업 프로세스도 launchd로 재부모화돼 PPID=1이 된다(macOS 재부모화는 실측으로 정상 동작 확인됨).
- **사용자 영향**: `config init --preset dev` + 데몬 ON 상태에서, 본인이 띄운 dev 서버/빌드/파이썬 스크립트가 고아가 되는 순간 grace_period(30초) 후 조용히 SIGKILL. 진행 중 작업 데이터 손실.
- **수정**: (1) 실행파일 basename 우선 매칭 또는 명시적 앵커 옵션 분리. (2) 프리셋 단독 어휘를 좁히기: `cargo.*(watch|build|test)`, `python.*(pytest|http\.server)` 등. (3) 최소한 `dev` 적용 시 "이 패턴은 당신의 실행 중 node/python/cargo도 매칭할 수 있습니다" 경고 + dry-run 우선 유도.

### C-5. 기본 `clean`이 무확인·즉시 SIGKILL (dry-run 없음)
- **위치**: `src/cleaner.rs:154`(`grace_period=0`), `cli.rs:63-80`(Clean), `kill.rs:107-112`(SIGKILL 에스컬레이션)
- **사실**: 비대화형 `clean`은 `grace_period=0`으로 덮어쓰고 스캔 즉시 SIGTERM → 5초 내 미종료 시 SIGKILL. `-i`(interactive)가 아니면 **대상 미리보기·확인이 전혀 없다.** 또한 가장 위험한 `clean`에만 dry-run 플래그가 없다(`start`엔 `-d` 있음). *적대적 검증 보정*: target 패턴 매칭 + whitelist 게이트가 있으므로 "임의 프로세스가 다 죽는다"는 과장이다. 실제 위험은 **광범위 설정(C-4) 사용자 + whitelist를 비껴가는 작업명**일 때.
- **수정**: 비대화형 `clean`도 죽이기 전 **대상 목록을 먼저 출력**하고 기본 확인(`--yes`로 생략)을 받거나, `clean --dry-run`을 추가. 플래그 의미 통일(`-d`=dry-run을 모든 destructive 명령에).

---

## 1. 기능 상의 문제점 (Functional)

| 이슈 | 위치 | 등급 | 검증 |
|------|------|------|------|
| 컨테이너 감지가 **경고만 하고 종료를 막지 않음** — devcontainer/CI 안에서 PID 1 reparent된 워크로드를 고아로 오판해 죽일 수 있음(PID 1/2는 가드로 보호되나 reparent된 자식은 PID>2) | `scanner.rs:87-92` | 높음 | confirmed |
| **통계 회전 시 과거 데이터 영구 손실** — 5MB 초과 시 `stats.jsonl.old`로 rename하지만 `show_stats`는 `.old`를 읽지 않고, 다음 회전이 직전 `.old`를 덮어씀 → `stats --days 30`이 과소 집계 | `daemon.rs:244-254`·`290` | 중간 | confirmed |
| stats 타임존/DST 취약: 오프셋 없는 `%Y-%m-%dT%H:%M:%S` 문자열을 사전식 비교 | `daemon.rs:222`·`287-301` | 중간 | unverified |
| `track` 시 대상 PID를 sysinfo에서 못 찾으면 `start_time=None`을 **조용히 저장** → 이후 세션 clean에서 그 PID는 재사용 방어가 비활성 | `session.rs:333-346` | 중간 | partial |
| `claude` 프리셋의 단독 `claude` 패턴이 경로/스크립트명에 'claude' 포함된 무관 프로세스를 오탐(부분일치) | `config.rs:381` | 중간 | partial |
| 탐지 스냅샷과 kill이 별도 System/시점 → 잔여 TOCTOU(초 단위 start_time이라 동일-초 PID 재사용은 우회 가능, 단 발생 조건 극히 좁음) | `scanner.rs`·`cleaner.rs`·`kill.rs` | 낮음 | partial |
| grace_period 추적이 in-memory `Instant`(`#[serde(skip)]`)라 데몬 재시작/재부팅 시 리셋 → 오래된 고아도 grace_period를 다시 채워야 정리 | `scanner.rs:37-38`·`182` | 낮음 | unverified |
| 빈 cmdline 프로세스는 매칭 시도 자체를 건너뜀(권한 부족 등으로 cmd() 빈 경우 탐지 불가) → `name()` 폴백 부재 | `scanner.rs:125-128` | 낮음 | unverified |

**핵심**: 컨테이너 가드를 "경고"에서 "차단(`--force-in-container` 요구)"으로 격상, stats는 `.jsonl`+`.jsonl.old` 둘 다 읽고 회전을 다단계(`.1/.2`)로, `track`은 PID를 못 찾으면 경고/거부.

---

## 2. 코드 개선점 (Code quality)

| 이슈 | 위치 | 등급 |
|------|------|------|
| `Config` 구조체에 `#[serde(default)]` 부재 — 향후 필드 추가 시 **기존 사용자 config가 파싱 실패**해 데몬이 죽음(마이그레이션 단절). 지금도 사용자가 부분 config를 손으로 쓰면 파싱 실패 | `config.rs:10-25` | 낮음→마이그레이션 리스크 |
| `main.rs`의 exit code를 **에러 문자열 부분일치**(`contains("permission denied")` 등)로 결정 — i18n/문구 변경에 취약, 깨지기 쉬움 | `main.rs:352-363` | 중간 |
| 전역 `--json`을 **절반의 서브커맨드가 무시**(tree/logs/session/doctor/version 등) → 스크립팅 일관성 저하 | `cli.rs`·`main.rs` | 중간 |
| `clean_filtered`와 `clean_interactive`가 필터·스캔 로직을 거의 그대로 중복 | `cleaner.rs:145-281` | 낮음(중복) |
| `visualize` 트리 빌드가 `ProcessRefreshKind::everything()`(CPU/메모리/환경까지)로 전수 새로고침 + 정규식 전수 매칭 → 프로세스 수천 개 머신에서 `tree` 느림. `RegexSet`+필드 축소 권장 | `visualize.rs:34-112` | 중간 |
| 포그라운드 로거가 file_layer+stdout_layer 이중 등록(데몬 stdout 리다이렉트 시 INFO 중복, `.with_ansi(false)` 미지정) | `logger.rs:43-57` | 낮음 |
| `ProcessNode.cmdline`을 80자로 트렁케이트해 보관하지만 `print_node`는 `name`만 출력(`#[allow(dead_code)]`) → 죽은 할당 | `visualize.rs` | 낮음 |
| 의존성 중복: `windows-sys` 3중, `nix` 0.29/0.30 2중, `thiserror`/`getrandom` 2중. ctrlc가 `nix 0.30`+`windows-sys`+`dispatch2`를 끌어옴 — 이미 `nix` 직접 의존이므로 **ctrlc 제거 후 nix sigaction 직접 사용**하면 C-1 해결 + 트리 정리 동시 달성 | `Cargo.toml`·`Cargo.lock` | 중간 |
| CI(`ci.yml`)는 네이티브만 빌드/테스트하는데 릴리스는 4개 크로스타깃을 빌드 → 크로스컴파일 깨짐이 **태그 당일에야** 발견. `--locked` 미사용(재현성), `rust-version`(MSRV) 미선언 | `.github/workflows/` | 중간/낮음 |

**핵심**: `serde(default)`로 config 전방호환성 확보 + 전용 에러 enum으로 exit code 결정 + ctrlc 제거(시그널 일원화)는 코드 품질과 C-1 버그를 동시에 잡는다.

---

## 4. 사용성 개선점 (Usability) — 배포·온보딩 포함

### Linux 배포가 사실상 깨져 있음 (높음, confirmed)
- **ExecStart 경로 불일치**: README는 `cargo install`(→ `~/.cargo/bin/proc-janitor`) 후 유닛 복사를 안내하는데, 유닛은 `ExecStart=/usr/local/bin/proc-janitor`로 하드코딩(`service:8`) → `status=203/EXEC`로 즉시 실패 + 5초마다 재시작 실패 반복. (`README.md:95-98`, `resources/proc-janitor.service:8`)
- **재부팅 미생존**: `systemctl --user enable` + `WantedBy=default.target`인데 **`loginctl enable-linger $USER`가 어디에도 없음** → 헤드리스/로그아웃 시 부팅 후 자동 실행 안 됨. (`README.md:93-99`)
- **ProtectHome 취약**: `ProtectHome=read-only` + `ReadWritePaths`는 **경로가 이미 존재해야** 동작. 첫 실행에 `~/.proc-janitor`/`~/.config/proc-janitor`가 없으면 `create_dir_all`이 마운트 네임스페이스에서 실패할 수 있음 → `ExecStartPre=/bin/mkdir -p ...` 또는 `StateDirectory=` 권장. (`service:14-16`)

### 첫 실행 체험 / 신뢰·안전 (높음)
- **curl|sh 설치(README 1순위)에 체크섬·서명 검증 0줄** — 프로세스를 죽이는 권한 데몬인데 변조 바이너리가 sudo로 `/usr/local/bin`에 설치될 수 있음. 릴리스는 `.sha256`를 발행하면서도 **설치 스크립트가 그걸 쓰지 않음**(반쪽). → 스크립트가 `${url}.sha256`도 받아 `shasum -a 256 -c`로 강제. (`scripts/install-binary.sh`)
- **curl|sh 경로는 자동시작을 설정하지 않음** — plist/systemd 등록 없이 바이너리만 복사 → "설치했는데 재부팅 후 안 도는" 침묵 실패. plist의 `StandardOutPath`(`~/.proc-janitor/logs/launchd.log`)는 부모 디렉터리를 launchd가 안 만들어줘 추가 실패 가능. → `proc-janitor install-service` 서브커맨드로 OS별 자동시작 등록 일원화 권장.
- **`uninstall.sh`가 brew/바이너리 설치 사용자에게 미작동** — 같은 폴더의 `install.sh`로 위임하는데 그 파일이 로컬에 없거나 macOS 전용 가드에 막힘. brew 경로는 `brew uninstall`이 바이너리를 지워 실害는 작지만, 안내에 `brew services stop`·`systemctl --user disable`이 빠짐. (`scripts/uninstall.sh`)

### 발견 가능성 / 안내
- **`doctor`와 "가이드 힌트"가 위험을 못 잡는다**: 기본값이 비어있지 않아(C-2) "타깃 미설정" 경고가 절대 안 뜬다. doctor가 "현재 설정이 당신의 실행 중 프로세스 N개와 매칭됨"을 **실제로 dry-match해서 보여주면** 첫 실행 사고를 예방할 수 있다.
- **문서 드리프트**: README/AGENTS.md/메모리가 "HTML 대시보드 + XSS 보호 + vis-network SRI"를 기정사실로 적지만 `visualize.rs`엔 HTML/innerHTML/serde_json이 전혀 없고 ASCII 트리뿐. HTML 명령도 CLI에 없음. → 문서 현행화(없으면 "ASCII 트리만" 명시), 추후 HTML 추가 시 cmdline은 공격자 영향 텍스트이므로 반드시 이스케이프.
- **인-레포 `Formula/proc-janitor.rb`가 v0.5.1로 방치** — 실제 배포 tap(`release.yml`이 생성)과 버전·방식·검증 모두 불일치. 문서화된 설치 경로에선 안 쓰이므로 실害는 낮으나 기여자 혼란. → 삭제하거나 릴리스가 함께 갱신.
- **Linux 데스크톱 알림 부재**: 정리 시 macOS는 osascript 알림, Linux는 완전 no-op. `notify-send` 있으면 fire-and-forget 권장.

---

## 6. 적대적 검증으로 **반증된** 주장 (= 실제로는 안전)

신뢰를 위해 명시: 아래는 자극적이지만 코드 확인 결과 **사실이 아님**.

1. **"macOS는 고아를 PID 1로 재부모화하지 않아 못 잡는다"** — 거짓. Darwin 실측에서 부모를 강제 종료한 자식이 2초 내 PPID=1(launchd)로 재부모화됨. 핵심 가치(고아 탐지)는 정상 동작.
2. **"self/부모 셸/터미널을 죽일 수 있다"** — 거짓. `--pid`는 kill 대상 주입이 아니라 **스캔 결과에 대한 필터**일 뿐(`cleaner.rs:172`). 대화형 셸은 PPID≠1이고 `proc-janitor` 자신의 cmdline은 어떤 기본 패턴에도 안 걸림. 상류 게이팅(PPID=1 + target 매칭)이 사실상 보호. *(단, kill 경로에 명시적 self-PID 가드 추가는 심층방어로 가치 있음 — C-4 self-kill 시나리오 참고)*
3. **"Apple Silicon에서 plist 경로(/usr/local/bin)가 깨져 부팅 시 데몬이 죽는다"** — 거짓. 이 plist는 `install.sh` 전용이고 install.sh가 바이너리도 `/usr/local/bin`에 넣어 경로가 항상 일치. brew는 Formula의 `service` 블록(opt_bin)으로 별도 plist 생성. *(남는 건 install.sh가 Apple Silicon 관례(/opt/homebrew)를 안 따르고 sudo 필요하다는 사소한 이식성 이슈뿐.)*

---

## 권장 처리 순서 (impact / effort)

1. **C-1 reload** — 사용자 데이터 없이 데몬만 죽으므로 즉시 수정(ctrlc 제거 + signal-hook). 동시에 의존성 중복도 해소.
2. **C-2 기본값 / C-4 프리셋 / C-5 무확인 clean** — "기본은 no-op, 위험 동작은 미리보기·확인" 원칙으로 묶어서. 한 PR로 안전 정책 재정립.
3. **C-3 세션 parent_pid** — `getppid()` + start_time 저장.
4. **Linux 배포(§4)** — ExecStart 템플릿화 + linger 문서 + ExecStartPre mkdir + install-binary 체크섬.
5. 기능 버그(stats 회전·타임존), 코드 품질(serde default·exit code·--json 일관성)은 후순위.
