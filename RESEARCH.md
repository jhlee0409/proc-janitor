# proc-janitor Research Notes

> 터미널 종료 시 고아 프로세스를 자동으로 정리하는 범용 데몬

## 문제 정의

### 현상
- 터미널(Ghostty, iTerm2, VS Code 등)을 닫아도 자식 프로세스(특히 Claude Code, Node.js)가 종료되지 않음
- 프로세스가 PPID=1 (고아 상태)로 남아 메모리 계속 점유 (각 ~200-300MB)
- 수동으로 `pkill -f claude` 실행해야 정리됨

### 근본 원인
1. **터미널이 SIGHUP을 제대로 전달하지 않음** - 창 닫기(Cmd+W)는 자식에게 시그널 안 보내는 경우 많음
2. **macOS에 Linux `prctl(PR_SET_PDEATHSIG)` 동등 기능 없음** - 부모 죽을 때 자식도 죽이는 네이티브 방법 부재
3. **Shell trap 한계** - 인터랙티브 셸에서 시그널 받으면 EXIT 트랩 실행 안 됨 ([참고](https://mywiki.wooledge.org/SignalTrap))
4. **프로세스 그룹 분리** - `setsid`, `disown`, 백그라운드 실행 시 터미널과 분리됨

## 기존 솔루션 분석

### 왜 기존 도구로 해결 안 되는가

| 접근법 | 한계점 |
|--------|--------|
| Shell trap (`trap cleanup EXIT`) | 인터랙티브 셸에서 시그널 받으면 EXIT 트랩 실행 안 됨 |
| Ghostty/터미널 설정 | 플러그인 시스템 없음, `confirm-close-surface`만 존재 |
| macOS 네이티브 | Linux의 `prctl(PR_SET_PDEATHSIG)` 동등 기능 없음 |
| launchd `AbandonProcessGroup` | 데몬용 설정, 터미널 앱에는 적용 어려움 |

### 관련 프로젝트 (참고용)

| 프로젝트 | 설명 | 한계 |
|----------|------|------|
| [orphan-reaper](https://github.com/maandree/orphan-reaper) | 프로세스 트리 subreaper | Linux 전용, 특정 용도 |
| [zps](https://github.com/orhun/zps) | 좀비 프로세스 리스팅/정리 | Linux 전용 |
| [phantom-killer](https://github.com/chris-sekira/phantom-killer) | PowerShell 좀비 킬러 | Windows 전용 |
| [node-cleanup](https://github.com/jtlapp/node-cleanup) | Node.js 종료 핸들러 | Node.js 앱 내부용 |
| [gastown orphan.go](https://github.com/steveyegge/gastown/issues/29) | Claude Code 고아 정리 | tmux 특화, 범용 아님 |

## 기술 설계 방향

### Option A: 폴링 기반 데몬 (권장 - 가장 단순하고 안정적)

```
proc-janitor (LaunchAgent)
├── 주기적으로 (5초마다) 프로세스 테이블 스캔
├── PPID=1인 대상 프로세스 탐지 (node, claude 등)
├── 일정 시간(grace period) 후에도 PPID=1이면 SIGTERM
├── 응답 없으면 SIGKILL
└── 로그 기록 (~/.proc-janitor/logs/)
```

**장점**: 구현 단순, 터미널 종류 무관, 안정적
**단점**: 폴링 오버헤드 (미미함)

### Option B: 프로세스 그룹 추적

```
1. 터미널 프로세스 시작 감지 (Endpoint Security API)
2. 해당 터미널의 프로세스 그룹 ID 기록
3. 터미널 종료 감지
4. 해당 프로세스 그룹 전체 SIGTERM
```

**장점**: 정확한 추적
**단점**: Endpoint Security API 복잡, 권한 필요

### Option C: PTY 기반 래퍼

```bash
# claude-wrapper
#!/bin/bash
trap 'kill $(jobs -p) 2>/dev/null' EXIT TERM HUP
exec claude "$@"
```

**장점**: 가장 단순
**단점**: 사용자가 래퍼 사용해야 함, 근본 해결 아님

## 권장 구현 스펙

### 핵심 기능

```yaml
name: proc-janitor
description: 터미널 종료 후 고아 프로세스 자동 정리 데몬

features:
  - PPID=1인 대상 프로세스 탐지
  - 설정 가능한 대상 프로세스 패턴 (node, claude, python 등)
  - Grace period 후 정리 (기본 30초)
  - SIGTERM → SIGKILL 순차 시도
  - 화이트리스트 (정리 제외 프로세스)
  - 로깅 및 통계
  - launchd 자동 시작
```

### 설정 파일 (~/.config/proc-janitor/config.toml)

```toml
# 스캔 간격 (초)
scan_interval = 5

# 고아 상태 유지 시 정리까지 대기 시간 (초)
grace_period = 30

# 정리 대상 프로세스 패턴 (정규식)
targets = [
    "node.*claude",
    "claude",
    "node.*mcp",
]

# 정리 제외 (화이트리스트)
whitelist = [
    "node.*server",
    "pm2",
]

# 로그 설정
[logging]
enabled = true
path = "~/.proc-janitor/logs"
retention_days = 7
```

### CLI 인터페이스

```bash
# 데몬 관리
proc-janitor start          # 데몬 시작
proc-janitor stop           # 데몬 중지
proc-janitor status         # 상태 확인

# 수동 실행
proc-janitor scan           # 한번 스캔 (dry-run)
proc-janitor clean          # 즉시 정리
proc-janitor clean --dry-run # 정리 대상만 표시

# 설정
proc-janitor config edit    # 설정 편집
proc-janitor config show    # 현재 설정 표시

# 로그
proc-janitor logs           # 최근 로그 보기
proc-janitor logs --follow  # 실시간 로그
```

### 디렉토리 구조

```
proc-janitor/
├── Cargo.toml
├── README.md
├── LICENSE (MIT)
├── src/
│   ├── main.rs           # CLI 엔트리포인트
│   ├── daemon.rs         # 데몬 로직
│   ├── scanner.rs        # 프로세스 스캔
│   ├── cleaner.rs        # 프로세스 정리
│   ├── config.rs         # 설정 관리
│   └── logger.rs         # 로깅
├── resources/
│   └── com.proc-janitor.plist  # launchd plist
└── scripts/
    └── install.sh        # 설치 스크립트
```

## 기술 스택 권장

| 영역 | 선택 | 이유 |
|------|------|------|
| 언어 | **Rust** | 안전성, 성능, 크로스 플랫폼 |
| 프로세스 API | `sysinfo` crate | 크로스 플랫폼 프로세스 정보 |
| CLI | `clap` | 표준 Rust CLI 라이브러리 |
| 설정 | `toml` + `serde` | 가독성 좋은 설정 포맷 |
| 로깅 | `tracing` | 구조화된 로깅 |
| 데몬 | `daemonize` crate | Unix 데몬화 |

## 배포 계획

1. **GitHub 릴리즈** - 바이너리 배포
2. **Homebrew Formula** - `brew install proc-janitor`
3. **cargo install** - `cargo install proc-janitor`

## 참고 자료

### macOS 프로세스 관리
- [launchd.plist man page](https://keith.github.io/xcode-man-pages/launchd.plist.5.html)
- [macOS Process Management Guide](https://osxhub.com/macos-process-management-ps-kill-launchctl-guide/)

### 프로세스 그룹 & 시그널
- [Shell Process Groups and CTRL+C](https://gist.github.com/CMCDragonkai/e2cde09b688170fb84268cafe7a2b509)
- [Bash Trap Command](https://phoenixnap.com/kb/bash-trap-command)
- [SIGHUP Wikipedia](https://en.wikipedia.org/wiki/SIGHUP)

### 관련 이슈
- [gastown orphan cleanup](https://github.com/steveyegge/gastown/issues/29) - Claude Code 고아 프로세스 문제

## 메모

- Ghostty는 아직 플러그인 시스템 없음 (2025년 기준)
- macOS Endpoint Security API는 강력하지만 권한 복잡 → 폴링 방식이 현실적
- Linux 지원도 고려하면 `sysinfo` crate 사용이 좋음
