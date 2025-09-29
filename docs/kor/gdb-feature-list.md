## GDB 기능/명령 레퍼런스 (요약판)

본 문서는 GDB 15 계열 기준 핵심 기능과 자주 쓰는 명령을 한국어로 요약한 것입니다. 각 섹션은 “무엇을 하는지”, “주요 하위 명령/인자”, “간단 예시”를 포함합니다. aarch64-linux-gnu 빌드에서도 동일하게 적용됩니다.

참고: GDB 내에서 상세 문서는 `help`, `help <class>`, `help <command>`, 연관 검색은 `apropos <word>`로 확인할 수 있습니다.

---

### 빠른 시작
- 실행 파일 로드: `file <path/to/binary>` 또는 `gdb <binary>`로 시작
- 원격 타깃 접속: `target remote <host:port>`
- 실행 시작: `run [args...]` / 중단: Ctrl-C / 종료: `quit`
- 흔한 약어: `bt`(backtrace), `ni`(nexti), `si`(stepi), `b`(break), `c`(continue), `n`(next), `s`(step), `fin`(finish)

---

## 1) 파일/심볼 관리 (files)
- 목적: 디버깅할 실행 파일/코어덤프/심볼을 지정하고 확인

주요 명령
- `file <exe>`: 현재 디버깅 대상 실행 파일을 설정
- `symbol-file <symfile>`: 심볼 파일(별도 .debug 등)을 로드/교체
- `add-symbol-file <file> <addr> [sec addr ...]`: 지정 주소에 추가 심볼 로드
- `core-file <core>`: 코어 덤프 로드
- `exec-file <exe>`: 실행 파일만 교체 (심볼 유지는 상황에 따라 다름)
- `sharedlibrary [regex]`: 공유 라이브러리 심볼 로드/재탐색
- `info files`/`info sharedlibrary`: 로드 상태 점검

예시
- `file ./a.out`
- `core-file core.1234`
- `add-symbol-file vmlinux 0xffff800010000000`

주의
- PIE/ASLR 환경에서는 `add-symbol-file` 주소 지정에 유의
- 심볼 버전 불일치 시 경고가 발생할 수 있음

---

## 2) 실행 제어 (running)
- 목적: 프로그램을 시작/중단/재시작하고 단계적으로 실행

주요 명령
- `run [args...]`/`start`: 프로그램 실행(메인까지 진행)
- `continue`/`c`: 다음 중단점까지 계속 실행
- `next`/`n`: 한 줄 단위 실행(함수 내부 진입 안 함)
- `step`/`s`: 한 줄 단위 실행(함수 내부 진입)
- `finish`: 현재 함수 리턴까지 실행
- `until [loc]`: 지정 위치/다음 라인까지 실행
- `reverse-continue|reverse-next|reverse-step`: 리버스 디버깅(지원 빌드/레코드 필요)
- `interrupt`: 실행 중인 타겟을 인터럽트(Ctrl-C와 유사)

예시
- `run --flag 1`
- `n` / `s` / `finish`
- `until 123` 또는 `until func_name`

주의
- 리버스 디버깅은 `record` 서브시스템 활성화가 필요할 수 있음(`record full`)

---

## 3) 중단점/워치포인트 (breakpoints)
- 목적: 코드/조건/데이터 변경 시점에 실행 정지

주요 명령
- `break|b <loc>`: 위치에 브레이크포인트 설정
	- loc 형식: `file:line`, `func`, `*addr`
- `tbreak <loc>`: 일회성 브레이크포인트
- `hbreak`/`thbreak`: 하드웨어 브레이크포인트(타겟 의존)
- `watch <expr>`: 데이터 쓰기 감시
- `rwatch <expr>`: 데이터 읽기 감시
- `awatch <expr>`: 읽기/쓰기 모두 감시
- `condition <bnum> <expr>`: 브레이크포인트 조건 지정
- `commands <bnum> ... end`: 브포 hit 시 자동 수행 명령 스크립트
- `ignore <bnum> <count>`: 처음 N번은 무시
- `enable|disable [bnum]`: 활성/비활성
- `delete [bnum]`: 삭제
- `info break`/`info watch`: 상태 조회

예시
- `b main` / `b file.c:42` / `b *0x400812`
- `condition 1 i>10` / `ignore 1 3`
- `commands 1` → `silent` → `bt 3` → `continue` → `end`

주의
- 하드웨어 워치는 수량 제한이 있음(아키텍처 제약)

---

## 4) 데이터/메모리 검사 (data)
- 목적: 변수, 표현식, 메모리 덤프/수정

주요 명령
- `print|p <expr>`: 표현식 평가/출력
- `set var <lvalue> = <expr>`: 변수/메모리 값 변경
- `x/<fmt> <addr|expr>`: 메모리 검사(eXamine)
	- fmt 예: `10x`(워드 10개를 헥사), `8gx`(8개 8바이트 단위), `20i`(명령어 디스어셈)
- `ptype <symbol|expr>`: 타입 정보 표시
- `display/undisplay <expr>`: 스텝마다 자동 출력 등록/해제
- `set print <option>`: 출력 포맷 옵션 제어(예: `pretty on`)

예시
- `p myvec.size()` / `p/x var` / `set var buf[0]=0`
- `x/16bx 0x7ffff7dd0000` / `x/20i $pc`
- `display/x $x0` (AArch64 레지스터 예)

주의
- 멀티스레드 환경에서 레이스로 값이 수시로 바뀔 수 있음

---

## 5) 스택/프레임 (stack)
- 목적: 콜스택 확인, 프레임 전환, 로컬 변수 조사

주요 명령
- `backtrace|bt [N]`: 스택 트레이스(N 프레임 제한)
- `frame <N>`/`select-frame <N>`: 프레임 전환
- `up`/`down [COUNT]`: 인접 프레임 이동
- `info frame`/`info args`/`info locals`: 현재 프레임/인자/로컬 조회
- `return [expr]`: 현재 함수에서 즉시 리턴(옵션으로 값 지정)

예시
- `bt 20` / `frame 3` / `info locals`

---

## 6) 디스어셈블/레지스터 (disassemble, info)
- 목적: 기계어 수준 분석

주요 명령
- `disassemble [/m|/s] [start, end]`: 현재/범위 디스어셈블(`/m`은 소스와 혼합)
- `x/ni $pc`: 현재 PC 기준 n개 명령어 표시
- `info registers [name]`: 레지스터 상태 표시
- `set $reg = <expr>`: 레지스터 값 수정

예시
- `disassemble /m main`
- `info registers` / `set $x0=0` (AArch64)

---

## 7) 소스 탐색/레이아웃 (list, layout, TUI)
- 목적: 소스 코드 탐색, TUI 모드 사용

주요 명령
- `list [loc]`: 해당 위치 소스 표시
- `layout <split>`: TUI 레이아웃 전환
	- split: `src`(소스), `asm`(어셈), `regs`(레지스터), `split`(소스+어셈)
- `tui enable|disable` 또는 `tui` 토글: TUI 켜기/끄기
- `refresh`: TUI 새로고침
- `winheight|winwidth`: 창 크기 조정

예시
- `layout split` / ``tui enable`` / `list main`

주의
- `text-user-interface`는 클래스 이름이며, 실제 명령은 `tui`/`layout`입니다. `text-user-interface`라고 입력하면 “Undefined command”가 납니다.

---

## 8) 스레드/프로세스/인페리어 (thread, inferior)
- 목적: 멀티프로세스/멀티스레드 타겟 제어

주요 명령
- `info threads` / `thread <ID>`: 스레드 나열/전환
- `thread apply <ID|all> <cmd>`: 특정/전체 스레드에 명령 적용
- `add-inferior`/`remove-inferiors`/`inferior <ID>`: 프로세스 단위 관리
- `attach <pid>`/`detach`: 실행 중 프로세스 부착/분리

예시
- `info threads` → `thread 3` → `bt`
- `thread apply all bt 5`

---

## 9) 원격 디버깅/타겟 (target)
- 목적: gdbserver/에뮬레이터/하드웨어 타겟 연결

주요 명령
- `target remote <host:port>`: 원격 접속
- `target extended-remote <host:port>`: 확장 원격(프로세스 생성 등)
- `monitor <cmd>`: 타겟 모니터에 직접 명령 전달(QEMU 등)
- `set architecture <arch>`: 아키텍처 지정(필요 시)
- `remote` 관련 `set|show` 옵션들: 패킷 시간초과, 전송 모드 등

예시
- `target remote 127.0.0.1:1234`
- `monitor reset halt`

---

## 10) 트레이스포인트 (tracepoints)
- 목적: 프로그램 정지 없이 트레이스 데이터 수집(임베디드/원격에서 유용)

주요 명령
- `trace <loc>` / `tbreak`와 유사하지만 멈추지 않음
- `actions <tpoint>`: 수집할 데이터 정의(`collect var, $regs` 등)
- `tstart`/`tstop`/`tstatus`: 트레이스 세션 제어/상태
- `tsave <file>`/`tdump`: 결과 저장/덤프

예시
- `trace func` → `actions $tp` → `collect $pc, $sp, var` → `tstart`

주의
- 타겟/전송 경로 지원이 필요하며 로컬 네이티브에선 제한적일 수 있음

---

## 11) 기록/리버스 디버깅 (record)
- 목적: 실행 기록을 남겨 과거 상태로 이동/역실행

주요 명령
- `record full|btrace|...`: 기록 모드 시작
- `tfind <start|end|range|pc>`: 기록 내 탐색
- `reverse-continue|reverse-step|reverse-next`: 역실행
- `tstop`: 기록 중지

주의
- 성능/메모리 비용이 크며 타겟 의존적

---

## 12) 검색/탐색 (search, find)
- 목적: 메모리/어셈블리/소스 내 검색

주요 명령
- `search <pattern>`: 어셈블리/메모리에서 바이트 시퀀스 검색
- `find [/size] <start>, <end>, <val1> [<val2> ...]`: 메모리에서 값 탐색
- `forward-search`/`reverse-search`: 소스 텍스트 검색

예시
- `find 0x400000, 0x410000, 0x90` (0x90 바이트 탐색)

---

## 13) 정보 조회 (info, show, status)
- 목적: 각종 상태/설정 확인

주요 명령
- `info functions|variables|types`: 심볼/타입 나열
- `info registers|args|locals|frame|files|sharedlibrary`
- `info break|watch|threads|inferiors|target`
- `show <setting>`: 설정 값 확인(예: `show architecture`)

---

## 14) 설정 (set/unset)
- 목적: 런타임 동작/표시/타겟 파라미터 변경

자주 쓰는 항목 예
- `set disassemble-next-line on` : 스텝 시 다음 명령어 표시
- `set pagination off` : 페이지 중지 비활성(스크립트 친화)
- `set print pretty on` : 구조체 보기 좋게
- `set follow-fork-mode child|parent`
- `set detach-on-fork on|off`
- `set {type}addr = value` : 임의 메모리 쓰기

설정은 `show <same-setting>`으로 확인 가능

---

## 15) 스크립팅/확장 (python, guile, define)
- 목적: 자동화, 사용자 정의 명령, 포맷터 확장

주요 명령
- `python`/`python-interactive`: 파이썬 실행/REPL
- `define <name> ... end`: 사용자 정의 명령
- `alias <new> = <existing>`: 별칭 생성
- `document <name> ... end`: 사용자 명령 도움말 추가
- `source <file>`: 스크립트/명령 파일 로드

예시
- `define pbt` → `bt 20` → `end` → 이후 `pbt`로 단축 실행

---

## 16) 빌드/컴파일 온더플라이 (compile)
- 목적: 런타임에 작은 C 코드를 컴파일해 주입/실행(Clang/LLVM 통합 필요)

주요 명령
- `compile code <c-snippet>`
- `compile print <expr>` / `compile file <c-file>`

주의
- 보안/안정성 고려, 최적화/ABI 일치 필요

---

## 17) 유틸리티/기타
- `shell <cmd>`: 쉘 명령 실행
- `save gdb-index|breakpoints|tracepoints <file>`: 상태 저장
- `generate-core-file [file]`: 현재 프로세스 코어 덤프 생성
- `dump memory|value|binary ...`: 메모리/값 덤프
- `whatis <expr>`: 타입 간단 조회
- `demangle <name>`: 맹글링 해제

---

## 18) 약어/자주 쓰는 콤보
- bt/fin/n/s/c, `display` 등록 후 스텝, `info regs`+`x/10i $pc`, `layout split` 후 `tui`

---

## 19) 문제 해결 팁
- “Undefined command: text-user-interface” 메시지: `tui`/`layout` 명령을 사용하세요.
- 심볼이 안 잡힐 때: `set substitute-path`, `directory <src_dir>`, `sharedlibrary` 재탐색 확인
- 최적화 바이너리: `set disassemble-next-line on`, `set print pretty on`, `ni/si` 혼용
- ASLR/PIE: 실제 로드 주소(`info proc mappings` 또는 `info files`)를 기준으로 심볼 추가

---

## 20) 참고 링크
- GDB 공식 문서: https://www.gnu.org/software/gdb/documentation/
- 명령 도움말: GDB 내부 `help`, `apropos`, `help all`

