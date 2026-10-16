# 작업 기록

완료된 항목의 기록입니다. 남은 작업은 [TODO.md](../TODO.md)에 있습니다.


## GUI

- [x] 커서 아래 단어 하이라이트 (리스팅·의사 코드, 레지스터는 rax/eax/ax/al 별칭까지)
- [x] 최근 파일 목록(File ▸ Open Recent), 창 크기·dock 배치 저장 (`QSettings`, `RELIC_SETTINGS`로 ini 경로 지정 가능)
- [x] 백그라운드 작업 취소·진행 표시: 상태 표시줄 진행 막대 + Cancel(`Ctrl+.`), 스레드별 취소 토큰(`relic/progress.py`)을 함수 탐색·xref·취약점 스캔·디컴파일 패스 사이에서 확인; 종료 시 기다리지 않고 취소(최대 2초, 넘으면 창을 숨기고 스레드 종료 후 닫음)
- [x] 취약점 스캔 실패를 "발견 없음"과 구분해 표시(`VulnsThread.failed`, 표에 오류 행)
- [x] CFG 레이아웃: Sugiyama 방식(`relic/gui/layout.py`) — back edge 역전, 최장 경로 층, 긴 간선 더미 노드 경로, barycenter 교차 최소화(`/bin/ls` 큰 함수 교차 16656 → 1248), isotonic 좌표 배치, 층 하단까지 수직으로 내린 뒤 꺾는 간선
- [x] CFG 교차 계산 가속: Fenwick 트리로 층 쌍마다 O(E log V) (3000-case switch 6000블록 2.0초 → 0.18초)
- [x] CFG 블록 접기: 선택한 블록(`-`) 또는 그것을 감싼 가장 안쪽 루프(`L`)를 노드 하나로, `+`/`=`나 더블클릭으로 펼침, 접힌 블록 주소로 이동하면 그룹 노드가 선택됨, 함수별로 세션 동안 유지
- [x] CFG 간선 묶음: 한 블록으로 들어오는 전방 간선이 3개 이상이면 블록 위 합류점에서 모이고, 3개 이상 나가는 블록(switch)은 공통 줄기로 내려와 갈라짐
- [x] 테마 전환(라이트/다크, `Ctrl+Shift+L`)과 코드 글꼴 크기(`Ctrl+=`/`Ctrl+-`/`Ctrl+0`): 모든 뷰·표·앱 팔레트에 즉시 반영, `QSettings`에 저장

## 스크립팅

- [x] 스크립팅 API(`relic/scripting.py`), GUI Python 콘솔(`Ctrl+Shift+P`, 기록, 여러 줄 문장), 플러그인(`RELIC_PLUGINS` / `~/.relic/plugins`의 `register(api)` → Plugins 메뉴, 오류는 콘솔에), `relic script`

## 패치

- [x] 바이트·NOP·조건 분기 반전(x86, ARM/Thumb, AArch64, MIPS)·어셈블(keystone), 재분석, 프로젝트에 저장·다시 적용, 패치된 파일 내보내기(`relic patch`, Edit 메뉴)
- [x] 디버거가 패치된 이미지를 실행(패치가 있으면 임시 디렉터리에 내보낸 사본, 세션을 닫으면 삭제), 패치 undo/redo(`Ctrl+Z` / `Ctrl+Shift+Z`, 패치·되돌리기 모두)

## 디버거 (로컬, GDB/MI, pwndbg식 GUI)

- [x] GDB/MI 레코드 파서·프로세스 래퍼(`relic/debugger/mi.py`), 세션(`session.py`): pty 입출력, 시작(entry/main)·계속·단계 실행·커서까지·중단·종료, 중단점, PIE 슬라이드(`to_live`/`to_static`), 레지스터 변경 추적, `telescope`, 백트레이스
- [x] GUI(`relic/gui/debugger.py`): 작업 스레드 컨트롤러, Registers·Stack·Backtrace·Code·Console 패널, Debug 메뉴(F9/F7/F8/F4/F2), 리스팅 pc·중단점 표시
- [x] vmmap 패널, 메모리(hexdump) 뷰(주소·gdb 식·Relic 이름), 레지스터·스택 값 더블클릭으로 리스팅/메모리 따라가기
- [x] 중단점 목록 패널(조건·활성/비활성·적중 횟수, 재실행 시 유지)
- [x] 하드웨어 watchpoint(쓰기/읽기/접근, 바이너리 전역·주소는 PIE 보정한 `*(T *)live`로, 크기 1/2/4/8, 그 밖은 gdb 식), 이름으로 중단점(바이너리 함수·`puts@plt`는 정적 주소, `puts` 같은 라이브러리 함수는 gdb pending 중단점으로 libc 안에서 멈춤), 중단점 패널에 종류 열·`Delete`로 삭제, 멈춘 이유(`watchpoint 3 …: 0 -> 0x4052a0`) 표시
- [x] 의사 코드 뷰에서 현재 문장(pc)·중단점 줄 표시
- [x] 레지스터·메모리 값 편집(Registers 패널 `E`/우클릭, Debug ▸ Set register / Write memory: hex·`"문자열\n"`·`0x…` 워드)

## 아키텍처별 분석 보강

- [x] **P0** 함수 단위 레지스터 상수 전파 패스(`analysis/constprop.py`): CFG 위 전방 데이터 흐름(합류점은 모든 선행자가 같은 값일 때만, 호출은 caller-saved 소멸), "주소" 플래그(pc 유래 값, 비-PIE 절대 리터럴)가 붙은 값만 데이터 참조로 기록 → 문자열·전역·GOT 슬롯 xref와 리스팅 주석
  - [x] x86-32 PIC: `__x86.get_pc_thunk.*` + `add` 로 만든 GOT 기준 레지스터
  - [x] AArch64: `adrp` + `add` / `ldr`
  - [x] ARM / Thumb: 리터럴 풀 `ldr rN, [pc, #off]`, `add rN, pc`, `adr`, `movw`/`movt`
  - [x] MIPS: `$gp` 고정(`_gp` = GOT + 0x7ff0), `lui` + `addiu`, GOT 슬롯 로드(PIE의 로컬 GOT 페이지 + `addiu`), 슬롯에서 읽은 `$t9`로 호출 이름
  - 문자열 xref 비율: armhf `ld.so` 1 → 513/842, aarch64 `ld.so` 0 → 409/836, `vuln32_pie` 0 → 10/10
  - [x] ARM/AArch64 즉치값은 주소로 보지 않음(`mov w0, #0xffff`가 PIE에서 함수 시작으로 잡히던 문제), 빈 구간 계산은 함수 범위가 아니라 블록 구간으로(멀리 떨어진 cold 블록이 사이 함수들을 가리던 문제), 구간 중간의 프롤로그도 종결 명령 뒤라면 인정
  - [x] x64 SysV / Win64, x86 cdecl: 디컴파일러가 복원한 호출 인자 사용 (x64는 블록 안 역추적으로 결론이 안 날 때만; GUI는 창을 먼저 띄우고 백그라운드에서 스캔)
  - [x] AArch64 x0–x7 (AArch64 리프터)
  - [x] ARM r0–r3 (ARM32 리프터)
  - [x] MIPS a0–a3 (MIPS32 리프터)
- [x] **P1** 점프 테이블: ~~x86-32 PIC(GOT 기준 오프셋)~~ (완료), ~~AArch64(`adrp`+`add` 테이블, `ldrb/ldrh/ldr` 항목, `adr` 기준, `add ..., sxtb #2`, 다른 블록의 `cmp`와 `mov` 별칭으로 범위)~~ (완료), ~~ARM(`addls pc, pc, rN, lsl #2`, `ldr pc, [pc, rN, lsl #2]`, Thumb `tbb`/`tbh`, `adr`+`ldr`+`add`+`bx` 오프셋 테이블)~~ (완료)
  - 상대 테이블은 후보 기준 주소들을 검증해서 선택
- [x] **P1** MIPS: GOT(`DT_PLTGOT`, `DT_MIPS_LOCAL_GOTNO`, `DT_MIPS_GOTSYM`, `DT_MIPS_SYMTABNO`) 기반 import(슬롯·`.MIPS.stubs` 스텁), 지연 슬롯을 분기 블록에 포함(`Insn.delay`, `Block.last`는 분기), `bal`은 호출(`bal .+8`은 pc 읽기), `jalr $t9`는 `lw $t9, off($gp)` 슬롯으로 이름·noreturn 판정
- [x] **P1** ARM Thumb 모드: 주소별 명령어 집합(`$a`/`$t` 매핑 심볼, 심볼·엔트리 LSB, `bl`은 유지·`blx label`은 전환), IT 블록(조건을 한 번에 디코딩), Thumb PLT 진입점(`bx pc`)
  - [x] 심볼 없는(stripped) ARM / Thumb / AArch64: `_start`의 리프트된 IR에서 `__libc_start_main` 첫 인자(GOT·리터럴 풀 슬롯)를 읽어 `main` 복원, 함수 사이 빈 구간의 프롤로그 스캔(A32/Thumb `push {…, lr}`, AArch64 `stp x29, x30`·`paciasp`·`bti c`)으로 포인터로만 쓰이는 함수(`win`) 발견

## 테스트 / 인프라

- [x] **P0** GitHub Actions CI (pytest, gcc 설치, Python 3.10 / 3.12 / 3.13)
- [x] case마다 함수를 호출하는 `switch` 샘플(`flow.c`의 `sw_calls`): x86-64/x86-32 × -O0/-O2 모두 점프 테이블 → `switch`, 재컴파일 검증
- [x] PE 테스트: MinGW x64/x86 샘플로 로더·COFF 심볼·IAT 호출 이름·checksec·vulns·디컴파일 (CI에 mingw 설치, 없으면 skip)
- [x] ruff 린트(`pyproject.toml`, E/F/W/B, CI `lint` job). 포맷터·import 정렬은 기존 줄바꿈 스타일과 맞지 않아 적용하지 않음

## 분석 정확도

- [x] C++ 심볼 디맹글링(`relic/demangle.py`: libstdc++ `__cxa_demangle`, 없으면 `c++filt`): 목록·리스팅은 전체 이름, 의사 코드 호출은 `ns::Cls::method`, 이름 해석은 원래·전체·짧은 이름 모두
- [x] PE: 예외 디렉터리(`.pdata`)로 함수 시작 시드(chained 항목 제외), TLS 콜백 이름(`tls_callback_N`) — stripped MinGW x64에서 함수 130 → 174개
- [x] 대형 바이너리 성능 1차: 빈 구간 스캔이 함수를 찾을 때마다 모든 블록 구간을 다시 정렬하던 것을 병합 구간 집합(`_Cover`)의 증분 갱신으로, `regs_access`는 처음 쓸 때 계산 — 정적 링크 vuln(1131 함수) 42초 → 17초

## 디컴파일러

설계: [docs/decompiler-plan.md](docs/decompiler-plan.md)

- [x] **P1** 단계 1 — IR 정의와 x86-64 리프팅 (`relic ir`, IR 인터프리터로 의미 검증)
- [x] **P1** 단계 2 — SSA, 상수/복사 전파, 죽은 코드 제거 (패스 전후 결과를 `interp`로 비교)
  - [x] 호출 규약 표(`arch.py`), SSA 구성(`ssa.py`: 지배자, phi, 이름 부여)
  - [x] 최적화 패스(`passes.py`): 상수 폴딩·대수 단순화, 상수/복사 전파, 단일 사용 load 전달, 플래그→비교식 복원, DCE
  - [x] 인터프리터의 SSA 실행 지원(phi, 호출 use/def, version-0 → 진입 레지스터)
  - [x] 최적화 IR의 문자열/교차참조(`refs.py`: `ir_xrefs`, `format_ir`), `relic opt` 커맨드
- [x] **P1** 단계 3 — 호출 인자/반환값 복원, 스택 변수
  - [x] 호출 인자 복원(`calls.py`, `sigs.py`): libc 시그니처 + 포맷 문자열 인자 수, `_chk` 변형, 내부 함수는 live-in 레지스터 프리픽스, 시그니처 없는 import·함수 포인터는 호출 직전에 설정된 인자 레지스터
  - [x] 스택 프레임 분석(`stack.py`): rsp_0 기준 오프셋, 슬롯 분류(retaddr/saved/canary/buffer/local), 버퍼 크기, 카나리 탐지, `relic opt` 프레임 요약
  - [x] 스택 슬롯 → 지역 변수(`var_c`, `buf_48`), 프롤로그 저장·카나리 검사 숨김(`cleanup.py`)
- [x] **P1** 단계 4 — 제어 흐름 구조화(if/while/switch) (`structure.py`)
  - [x] 지배자/후지배자, 자연 루프, if/else, while, do-while, while(1)+break/continue, switch, goto 폴백
  - [x] switch case 값(점프 테이블 인덱스), bounds check → `default`, case 끝 `break`
  - [x] 루프 밖 합류점 → 명시적 `break`, 작은 공유 꼬리 블록·반환 블록은 goto 대신 복제
  - [x] 모든 도달 가능 블록이 정확히 한 번 출력되는지 구조 불변식으로 검증
  - [x] `X = init; while (c) { ...; X += k; }` → `for` (본문에 그 루프의 `continue`가 있으면 만들지 않음)
  - [x] if-else-if 사슬 → switch(`decompiler/chains.py`): 빠져나가는 `if (x == C)` 연속(나머지는 switch 뒤에), 일관성을 검사한 범위 분할 병합(gcc 이진 탐색 비교 트리), 본문이 이어지는 else-if 사슬은 `break`·`default`; 루프를 겨냥한 `break`가 든 본문은 변환하지 않음. AArch64 -O2 `sw_calls`가 8-case switch로
  - [x] `-O2` goto 줄이기 1차: 단락 평가 `&&`/`||` 결합, 후지배자 없는 if의 합류점 선택, 작은 비순환 꼬리 영역 복제(6블록/12문장) — `/usr/bin/{true,cat,gzip}` goto 1911 → 1469
  - [x] 상수 나눗셈·나머지 복원(`arith.py`): 매직 넘버 곱셈 → `x / c`, `x % c`, 곱셈 역원 비교 → `x % c == r` (부호·음수 제수·64비트, 평가로 검증)
  - [x] 부호 있는 2의 거듭제곱 나눗셈·나머지(`(x < 0 ? x + 15 : x) >> 4` → `x / 16`, `% 8`)
- [x] **P1** 단계 5 — out-of-SSA, 타입, C 출력 (`outssa.py`, `vartypes.py`, `pipeline.py`, `emit.py`)
  - [x] phi → 복사 + 간섭 기반 병합(인터프리터로 검증), 단일 사용 임시 변수 인라인
  - [x] void / 반환 폭(호출자가 읽는 폭), 변수 폭 축소(`low32` 제거), 포인터·unsigned 추론, 복사로 포인터 타입 전파
  - [x] 시그니처·지역 변수 선언, 문자열·심볼·배열 인덱스, 포인터 산술 원소 단위, `&&` 조건, else-if, early return
  - [x] 줄 ↔ 주소 매핑(`Decompiled.lines`, `relic decompile --addrs`)
  - [x] 재컴파일 테스트: `checksum`/`classify` 디컴파일 결과를 gcc로 다시 컴파일해 원본과 비교
  - [x] 사용자 이름 변경(`Analysis.renames`)·주석·변수 이름(`Analysis.var_names`)을 의사 코드에 반영
  - [x] 구조체 복원(`decompiler/structs.py`): 포인터 변수·매개변수·전역 포인터·전역 포인터 배열 원소(`notes[i]`)를 기준으로 고정 오프셋 접근을 모아 필드로(폭이 둘 이상이거나 포인터/정수 필드가 섞이거나 전역 포인터 배열 원소), 전역 기반 구조체는 그 전역을 참조하는 모든 함수에서 공유(`notes[i] = v3`처럼 슬롯에 저장된 지역 포인터도 같은 구조체), 필드 타입은 `malloc` 저장 → `void *`, 포맷·문자열 인자 → `char *`, 주소로 쓰임 → `void *`; 출력은 `p->f_8`, `&p->f_8`, 함수 위에 패딩 포함 `struct` 정의. 이름 변경(`N`, `rename_struct`/`rename_field`, 프로젝트에 저장). `structs.c`를 디컴파일·재컴파일해 원본 구조체로 호출 비교(-O0/-O2)
  - [x] 데이터 객체 안·바로 뒤 주소는 `(char *)&pool + 32`(루프 끝 포인터가 원본 주소 숫자로 나오던 것)
  - [x] 중첩 구조체: 필드에서 읽은 포인터를 기준으로 쓰면 그 필드의 구조체(`n->it->count`, 필드 타입 `struct s_x_8 *`), `n = n->next`는 자기 참조 필드(`struct s *next`), 가리키는 구조체를 먼저 선언, `-O0` 스택 복사본(`var_20 = a1`)의 구조체를 매개변수에도
  - [x] 타입 직접 지정(`Y`, `set_type`/`set_field_type`): 변수·매개변수에 C 타입(`unsigned int`, `char *`, `struct item *`), 복원된 구조체를 이름으로 다른 함수에 적용(그 함수의 접근으로 필드가 늘어나고 모든 함수가 같은 정의를 공유), 필드 타입 지정(`struct item *`이면 중첩 접근이 그 구조체로), 없는 구조체 이름은 주석으로 알림, 이름 붙이거나 적용한 구조체는 레이아웃을 프로젝트에 저장(새 세션에서도 적용), 필드 복사 변수는 필드 포인터 타입(`char *v1 = a1->name`)
  - [x] 함수 간 통합: 호출자가 전역 구조체 포인터(`pool[0]`, `notes[i]`)를 넘기는 매개변수는 그 구조체(꼬리 호출 포함), 피호출자의 접근도 전역 구조체의 필드로; `pool`과 `pool[i]`는 같은 종류의 키, 배열 객체 첫 원소 읽기는 `pool[0]`(이름만 쓰면 배열 자체)
  - [x] 포인터 크기 칸이 쓰임새로만 갈리는 경우(`argv[0]`, `argv[1]`)는 구조체가 아님
  - [x] 지역 구조체의 매개변수 통합: 호출자가 자기 구조체(`it = malloc(...)`)를 넘기면 피호출자 매개변수는 그 구조체, 피호출자가 매개변수로 읽는 필드도 호출자 쪽 구조체에(전역 출처가 있으면 그쪽 우선); 넓은 필드의 하위 바이트 읽기는 `*(short *)&p->f_10`
  - [x] 0 확장 출력 수정: 부호 있는 좁은 값을 넓힐 때 `(unsigned int)(unsigned short)x`(전에는 `(unsigned int)(short)x`로 부호 확장되는 C가 나옴)
  - [x] 배열 필드: `base + k + i*s`(덧셈 순서 무관, 바이트 배열은 배율 없이) → `p->f_8[i]`, 상수 첨자 접근은 같은 배열의 원소, 길이는 다음 필드까지(뒤에 없으면 flexible `[]`), 프로젝트 레이아웃에도 길이 저장; 구조체 포인터의 바이트 오프셋(루프 끝 포인터)은 `(char *)p + n`
  - [x] 호출자 없는 함수의 반환값 판정: 어떤 경로에서 진입 시 반환 레지스터 값이 그대로 돌아갈 수 있으면 반환값 없음(`-O0`에서 `rax`를 임시로 쓰던 void 함수가 `rax`를 반환하던 것)
  - [x] 구조체 편집 창(View ▸ Structures, `Ctrl+Shift+S`): 복원·저장된 구조체 목록, 필드 표(오프셋·이름·타입·크기)에서 이름·타입 바로 수정, 필드 추가(`0x10 char[8] tag`)·삭제, 구조체 이름 변경; 손으로 한 추가·삭제는 프로젝트에 저장되어 다음 세션의 복원 결과에도 적용(`add_field`/`remove_field`)
  - [x] GUI Pseudocode 탭(`Tab`/`F5`): 지연 디컴파일·캐시, 리스팅과 커서 주소 동기화, 이름 변경 반영, 더블클릭 이동
  - [x] 디컴파일은 백그라운드 스레드에서(한 번에 하나, 진행 중 표시, 오래된 결과 폐기)
  - [x] 의사 코드에서 변수·매개변수 이름 변경(`N`, 프로젝트 파일에 저장), 사용자 주석 표시
  - [x] AArch64 리프터(`lift/arm64.py`): 시프트·확장 피연산자, pre/post-index, ldp/stp, csel/cset/ccmp, 비트필드, cbz/tbz, NZCV(C=no-borrow); AAPCS64, `__stack_chk_guard` 카나리, `adrp` 페이지를 코드 참조로 오인하지 않음
  - [x] ARM32 리프터(`lift/arm.py`): A32·Thumb-2, 조건 실행(`movgt` → `c ? new : old`, 조건부 호출/리턴은 합성 블록), 배럴 시프터 캐리, 리터럴 풀 상수, ldm/stm/push/pop, `__aeabi_idiv(mod)` → `/`·`%`, cbz/cbnz, strex; AAPCS(r0–r3), 정렬용 `push {r3, lr}` 숨김, ARM PLT 스텁 해석
  - [x] 공통 개선(ARM에서 발견): 루프에서 스택 버퍼를 훑는 포인터 phi를 고정 스택 주소로 잘못 보던 버그 수정, 조건 플래그 중복 전파(술어 실행), `c ? x : !c` 류 정리, 단독 GOT 슬롯 → `&stdout`
  - [x] AArch64 점프 테이블(`flow.c`의 12-case `sw_big`, 모든 아키텍처에서 재컴파일 검증)
  - [x] 호출 간 레지스터 보존(gcc `-fipa-ra`): 바이너리 안 함수 호출은 피호출 함수가 (전이적으로) 쓰는 레지스터만 덮어쓴다고 보고(`decompiler/clobbers.py`), import·간접 호출·미해결 점프·syscall은 ABI 전체. 이전에는 `gcd(y, 4) - sc_or(y, 9)`가 `sc_or(gcd(y, 4), 9)`와 미정의 변수로 나왔음
  - [x] 32비트 `int` 매개변수에 넘기는 음수 상수: 피호출 함수가 인자 레지스터를 하위 32비트로만 읽으면 `0xfffffffb` 대신 `-5`
  - [x] MIPS32 리프터(`lift/mips.py`, o32): 지연 슬롯은 분기 조건·호출 대상을 먼저 계산한 뒤 슬롯 명령, 그다음 분기(`lift_delayed`), `$gp`는 상수 `_gp`(쓰기·cprestore 저장 무시), 로컬 GOT 항목은 링크 시 상수, `jalr $t9`는 GOT 슬롯의 import 이름, hi/lo(mult/div), movn/movz, ext/ins; 점프 테이블(절대·`$gp` 상대 `.gpword`, `sltiu` 범위). 재컴파일 검증은 mipsel-gcc `-static` + `qemu-mipsel`
  - [x] 공통 개선(MIPS에서 발견): 스택 프레임의 반환 주소 슬롯은 x86 계열만(진입 sp+0은 호출자 영역: o32 인자 홈 슬롯 `arg_0`), 콜리 저장 레지스터 요약이 capstone `regs_access` 없는 아키텍처는 리프트 결과로, import GOT 슬롯을 통한 호출은 이름으로 출력, 가드 주소를 레지스터에 두는 카나리 인식, 분기형 부호 보정(`if (x < 0) x += 15`, 두 return)을 select로 바꿔 `/ 16`·`% 8` 복원, `sltiu x, 1` → `x == 0`
  - [x] x86-32: cdecl 스택 인자, 스택 매개변수(`a1`…), PC 썽크(`__x86.get_pc_thunk.*`, stripped는 본문으로 인식), `main`의 스택 재정렬, GOT 경유 전역(`stdout`)
  - [x] RISC-V RV64GC 리프터(`lift/riscv.py`, LP64D): 정수(RV64IMC, Zba/Zbb 일부), `w` 연산은 하위 32비트 계산 후 부호 확장, 압축 명령(`c.ldsp`·`c.addi16sp`·`c.addi4spn` 등, capstone이 메모리 피연산자를 즉치값+기준 레지스터로 줌), `auipc`/`lui` 쌍은 상수, `jal`/`jalr` 호출·`ret`·`j`/`jr` 꼬리 호출, F/D 부동소수점(산술·`fmadd` 계열→`fma`·비교·변환·`fmv`), `__global_pointer$`가 있으면 `gp`는 상수
    - 호출 규약: a0–a7 / fa0–fa7 인자, a0 / fa0 반환, s0–s11·fs0–fs11 콜리 저장; 가변 인자 함수의 `double`은 정수 레지스터(`printf("%f")`), fa0–fa7이 다 차면 남은 `double` 인자는 정수 레지스터로(피호출 쪽에서 `fmv.d.x`/스택 경유 `fld`로 확인해 순서 복원)
    - 분석: 분기·`jal` 대상은 pc 상대, PLT 스텁(`auipc t3; ld t3; jalr t1, t3`)은 점프이고 import 이름, `auipc`+`addi` 상수 전파로 문자열 xref, 리스팅에서 호출 대상 이름, 점프 테이블(`auipc`+`addi` 기준, `lw` 오프셋/`ld` 절대 항목, `bltu` 범위), pyelftools가 모르는 RISC-V 재배치 이름, `.got`의 `R_RISCV_64`는 데이터 import(`stdout`), stripped 바이너리 프롤로그 스캔(`addi sp, sp, -n`), 인자 추적 취약점 탐지
    - 공통 개선(RISC-V에서 발견): 부호/0 확장된 두 값(또는 들어맞는 상수)의 비교는 안쪽 폭으로(`(int64_t)x <= 1` → `x <= 1`), 정의가 모두 부호 확장인 변수(비트 연산·작은 0 확장·복사 포함, 낙관적 고정점)는 통째로 비교·비트 연산돼도 `int`로 좁힘, RISC-V `int` 매개변수(하위 32비트 읽기나 부호 확장 값과의 비교가 근거), 부호 확장 상수 반환(`li a0, -1`)은 `int`, float 매개변수를 그대로 돌려주는 경로는 반환 폭 판단에서 중립, 여러 번 쓰는 읽기 전용 상수 로드는 사용처마다 리터럴
    - 재컴파일 검증: riscv64-gcc `-static` + `qemu-riscv64` (flow·floats, -O0/-O2)
  - [x] C 헤더 가져오기(`decompiler/cheader.py`, `Analysis.import_header`, `relic types`, `relic decompile --header`, File ▸ Import C header, 스크립팅 `import_header`)
    - 파서: 구조체·공용체(익명·중첩)·열거형(상수식, `sizeof`, 앞 열거자 참조)·typedef(`typedef struct { … } point;`는 이름을 그대로, 출력도 `point`)·함수 원형(본문은 건너뜀)·함수 포인터·다차원/유연 배열, 주석·전처리 줄·`__attribute__` 무시; 비트필드·알 수 없는 타입·정의되지 않은 매크로는 줄 번호와 함께 거부(가져오기 전체 취소)
    - 레이아웃: 대상 ABI(LP64, Windows LLP64, ILP32, i386 SysV의 8바이트 정렬 4) — gcc `offsetof`/`sizeof`와 x86-64·i386·ARM·AArch64에서 일치를 테스트로 확인
    - 디컴파일러: 구조체는 태그 이름으로(중첩 구조체는 `p->hdr.len`으로 펼침, 공용체는 가장 큰 멤버), 선언은 헤더에 적힌 그대로(값으로 담은 구조체 먼저, 사용자가 필드를 고치면 복원 레이아웃 보기로), 함수 원형은 매개변수·반환 타입(`char *state_name(enum state a1)`; 반환 타입은 반환 폭 축소에도 반영, `Y`를 함수 이름에서 누르면 반환 타입 지정), 복사(`var_c = a1`)로 열거형·구조체 포인터 타입 전파
    - 열거형 출력: 비교·대입·저장·복합 대입·switch case·내부 함수 인자의 상수를 열거자 이름으로, 모두 2의 거듭제곱인 열거형은 플래그 조합(`OPT_VERBOSE | OPT_DRY`), 비트 검사(`tbz`: `((o >> 2) & 1) != 0`)는 `(o & OPT_DRY) != 0`
    - 프로젝트에 저장(`c_types`), 가져오기 한 번이 undo 한 단계; 두 번째 헤더는 앞 헤더의 typedef·구조체·열거자를 씀
    - 검증: `tests/src/types.c`를 -O0/-O2로 빌드해 헤더를 가져온 의사 코드를 헤더와 함께 다시 컴파일, 원본과 같은 입력으로 실행해 출력 비교
  - [x] 라이브러리 함수 원형: `decompiler/libc_h.py`의 libc·POSIX·소켓·mmap·프로세스·dl/pthread 원형 약 180개(`sigs.lookup`이 기존 표 다음으로 참조) — 인자 수(`socket(2, 1, 0)`, `mmap(0, n, 3, 34, -1, 0)`), 정확한 포인터 타입, 결과 타입; `int` 매개변수에 넘긴 64비트 상수는 32비트로(`-1`), 형식 없는 가변 인자 함수(`execl`)는 고정 인자 + 호출 전에 설정된 레지스터
    - 헤더의 원형이 표보다 우선: import 함수 원형은 호출 모양, 마지막 고정 인자가 `fmt`/`format`인 가변 인자 함수는 printf처럼 형식에서 인자 수(내부 래퍼 `log_msg(2, a1)`도), 형식 문자열 취약점 검사가 그 래퍼까지(`log_msg() called with a non-constant format string`), `double` 매개변수는 부동소수점 레지스터로 배치
  - [x] 비트필드: System V 배치(정렬 경계의 `sizeof(T)` 컨테이너, 0폭 비트필드, 이름 없는 비트필드는 정렬에 영향 없음, i386 `long long` 정렬 4) — gcc와 x86-64·i386·ARM에서 일치; 같은 저장 단위의 비트필드는 필드 하나, 선언은 헤더 그대로(`unsigned int version : 4;`); 읽기 `(unit >> k) & mask`·좁은 로드·한 번 읽어 둔 변수·`(unit & 0xe0) == 0x40` 비교를 `p->version`, `p->flags == 2`로; 비트필드가 아닌 저장 단위 접근은 일반 메모리 표기(이름·주소가 없으므로)
  - [x] `#define NAME 상수식`: 배열 크기·열거 값에 사용(함수형 매크로·상수가 아닌 값은 무시)
- [x] 의사 코드 내보내기: 바이너리 전체를 C 파일 하나로(구조체 선언은 맨 앞에 한 번씩, 함수는 주소 순서와 주소 주석, 실패한 함수는 이유 주석) — `relic decompile -a -o out.c`, File ▸ Export pseudocode(백그라운드, 진행 표시·취소, 취소하면 반쯤 쓴 파일을 남기지 않음), 스크립팅 `export(path)`
- [x] C 타입 창(View ▸ C types): 가져온 열거형(값)·typedef·구조체(필드)·함수 원형 목록, 헤더 가져오기, 모두 지우기(undo 한 단계, `Analysis.clear_imported_types`)
- [x] 변수로 계산한 점프 대상(`v2 = base + table[v1]; goto *v2`, PIE의 상대 점프 테이블)도 switch 색인으로: `switch (v1)`과 case 값, 대상 계산문과 그 변수는 출력에서 빠짐
- [x] 디컴파일러 속도(P0): 함수마다 최적화 SSA를 한 번만 — 호출자가 매개변수를 추정하려고 만든 최적화 SSA(`_entry_opt`)를 `decompile_ir`가 복사해 호출 복원(이전에는 lift·SSA·최적화를 두 번), 부동소수점 결과가 없으면 캐시된 SSA의 복사본을 최적화, 스택 매개변수 계산도 캐시 사용; 나눗셈 판별식(`x % c == r`) 인식이 후보마다 최대 4c(최대 26만)번 식을 평가하던 것을 1024개 + c의 배수로(모든 후보는 기존 표본으로 검증하므로 결과 동일); `IRFunction` 깊은 복사는 문장·컨테이너만 새로(식은 불변이라 공유); `_rewrite`의 변경 비교는 새 객체만. `/usr/bin/find` `main` 단독 20분 이상 → 14초, 테스트 바이너리 전체 출력 동일하게 69초 → 46초, 테스트 스위트 72초 → 38초

## 완료

- [x] ELF / PE / RAW 로더
- [x] 멀티 아키텍처 디스어셈블러
- [x] 함수 탐색, CFG, noreturn, tail call, x86-64 점프 테이블
- [x] stripped 바이너리 `main` 복구, 프롤로그 스캔
- [x] xref, 문자열, checksec, 포너블 휴리스틱(x86-64)
- [x] 프로젝트 저장(이름 변경·주석)
- [x] CLI, pytest 스위트
- [x] GUI 뷰 위젯(디스어셈블리 / CFG / 헥스)
- [x] GUI 메인 윈도우: 함수 목록, 백그라운드 분석, 이동 히스토리, 이름 변경·주석·xref, 정보 테이블, 스모크 테스트
- [x] ELF 재배치 타입 이름 기록 (GLOB_DAT import 해석)
- [x] x86-64 디컴파일러 단계 1–5 (`relic decompile`)
- [x] 구조화 정확성: 구조화된 트리를 실행해 CFG와 같은 블록 순서를 밟는지 무작위 그래프로 비교하는 테스트, 그것으로 찾은 버그 수정 — 한쪽이 건너뛰는 합류점, 분기 안에서 만난 do-while 래치(`continue`), 루프 follow이자 영역 끝인 꼬리(`break`), 바깥 루프의 헤더·follow로의 점프(`goto`), 영역 끝으로 바로 가는 분기; 점프 테이블(switch) 포함 — 다음 case로 이어지는(fall-through) 분기·복사된 꼬리, 서로 다른 끝으로 가는 두 분기
- [x] 라이브러리 시그니처(FLIRT 방식): 정적 라이브러리(`ar` + 재배치 ELF)에서 재배치 바이트를 가린 함수 패턴, 앞 16바이트 마스크별 색인, 가장 긴 일치·끝 위치 확인·별칭 묶음·참조 이름으로 모호성 해소, IFUNC 리졸버와 IRELATIVE 스텁 이름, noreturn 이름이면 함수 다시 찾기, `relic sigs`, GUI 적용
- [x] 리스팅의 함수 내부 데이터: 블록 사이·마지막 블록 뒤의 바이트를 빈 줄 대신 데이터로 — ARM/Thumb·AArch64 리터럴 풀(`.word`, 그 슬롯을 읽는 명령 `<- vuln+0x28`, PIC `ldr`+`add rX, pc`는 만들어지는 주소 `pc + 0x250 = "name?"`, GOT 오프셋은 `[x@got]`), Thumb `tbb`/`tbh`·ARM `ldr pc` 표(`jumptable_…`, `case k -> loc_…`), x86 정렬 패딩(`align 16`), `$a`/`$t` 매핑 심볼이 코드라고 하는 구간·x86의 도달하지 않는 코드는 `not reached`(미해결 간접 점프가 있는 함수면 그렇다고 표시); 다른 함수의 블록이 낀 구간은 건너뜀
- [x] 모든 편집의 undo/redo(`Analysis.undo`/`redo`, GUI `Ctrl+Z`/`Ctrl+Shift+Z`): 이름·주석·변수 이름·타입·구조체 편집·북마크는 편집 전 주석 상태를 기록(바뀐 게 없는 편집·실패한 편집은 기록하지 않음, 중첩 편집은 한 단계), 패치와 같은 기록에 순서대로; 되돌린 위치로 커서 이동. 북마크(`Alt+M`, Bookmarks 패널 `Ctrl+M`, 프로젝트에 저장)
- [x] x86-64 SSE 스칼라 부동소수점(`fp.py`, `fpabi.py`, `fpconst.py`): `movss/movsd`, `add/sub/mul/div/min/max/sqrt/round`, `cvtsi2sd`·`cvttsd2si`·`cvtss2sd`(변환은 정수 패스가 건드리지 않는 내장 함수), `comisd/ucomisd`의 ZF/PF/CF를 결과 집합 진리표로 접어 비교 하나로(`ja` → `a > b`, `jp`+`jne` → `!=`), 부호 마스크 `xorpd`/`andpd` → `-x`/`fabs`; xmm 인자(SysV 순서·Win64 위치, printf 형식의 `%f`, libm 시그니처)와 xmm0 반환값(호출자가 읽는 폭, 아니면 모든 반환 경로의 마지막 쓰기 — xmm 사이 복사를 따라감), `.rodata` 상수 → `3.0`·`1.5f` 리터럴, `double`/`float`·`double *` 타입. `tests/src/floats.c`를 -O0/-O2로 디컴파일해 다시 컴파일한 결과가 원본과 비트 단위로 같음; 최적화 전후 IR을 NaN·부호 있는 0 포함 입력으로 비교. mawk `__asm` 291 → 36
- [x] `main`의 매개변수: `int main(int argc, char **argv[, char **envp])` 이름·타입(복사본까지), 쓰지 않는 `argc` 뒤의 `argv`도 매개변수로; 포인터의 포인터 인덱싱(`argv[1]`)
- [x] 카나리 검사 찾기(`_reaches_tls`)의 지수 시간: phi로 그래프가 된 SSA 정의를 사용처마다 깊이 4까지 다시 훑던 것을 (변수, 깊이) 메모로 — mawk `main` 530초 → 31초, mawk 전체 620초 → 62초(시간 초과 2 → 0)
- [x] AArch64 스칼라 부동소수점: `fadd/fsub/fmul/fdiv/fnmul/fneg/fabs/fsqrt/frint*/fmax(nm)/fmin(nm)`, `fmov` 즉치값·레지스터, `movi d0, #0`, `scvtf/ucvtf/fcvtz[su]/fcvt[mpan]s/fcvt`, `fcmp(e)`의 NZCV(lt 1000, eq 0110, gt 0010, un 0011)를 결과 집합으로, `fcsel`, `fmadd/fmsub/fnmadd/fnmsub` → `fma()`(반올림 한 번이라 `a * b + c`로 쓰면 결과가 달라짐); AAPCS64 v0–v7 인자·v0 반환값, d8–d15 저장 슬롯 숨김. `floats.c` AArch64 -O0/-O2 재컴파일(qemu-aarch64)도 비트 단위로 같음. out-of-SSA 임시 변수 이름을 `_vN`으로(AArch64 `v1` 레지스터와 같은 이름이라 매개변수와 합쳐지던 문제)
- [x] 레지스터보다 많은 인자(x86-64 SysV/Win64, AArch64): 호출 쪽은 나가는 인자 영역(`[rsp]`, `[rsp+8]`…, Win64는 홈 공간 32바이트 뒤)의 저장을 인자로 거두고, SysV/AAPCS64는 정수·실수 레지스터를 따로 채우므로 7번째 정수 뒤의 `double`도 xmm으로 배치; 피호출 쪽은 스택 매개변수(`arg_8`…), 스택으로 받은 `double`도 실수로 표시. 긴 `printf`의 인자 15개가 모두 나옴, 시그니처가 `char *`라는 인자는 앞에 NUL이 없어도 문자열 리터럴로
- [x] 플러그인 훅: `api.add_line_decorator(fn)`(리스팅 줄에 주석·배경색), `api.on_analysis(fn)`(분석·재분석 후), `api.on_cursor(fn)`(커서가 다른 주소로); 훅의 예외는 훅마다 한 번 콘솔에 보고
- [x] -O0 비교 트리 → `switch`: 테스트 사이의 빈 블록이 else-if 사슬을 끊던 것(`x > K` 범위 갈래가 default로 가는 gcc -O0 이진 탐색), 재컴파일 비교 테스트
- [x] ARM32 VFP(armhf, ELF `EF_ARM_ABI_FLOAT_HARD`): `s2k`/`s2k+1`은 `dk`의 아래·위 절반(쓰기는 병합, 읽기는 최적화 패스가 그 절반에 쓴 값으로), `vadd/vsub/vmul/vdiv/vneg/vabs/vsqrt`, 반올림 두 번인 `vmla/vmls/vnmla/vnmls`와 한 번인 `vfma/vfms`, `vcvt`(고정소수점 포함)·`vcvtr`, `vcmp(e)` + `vmrs APSR_nzcv`, `vmov` 모든 형태(즉치값·코어 레지스터 쌍), `vldr`(리터럴 풀 상수)·`vstr`·`vpush`·`vpop`·`vldmia`; AAPCS-VFP 인자 배치(빈 단정도 슬롯 back-fill, 스택으로 넘어간 뒤는 모두 스택), 가변 인자 호출은 기본 규약(`double`은 `r2:r3` 쌍 또는 8바이트 정렬 스택), d0 반환값, d8–d15 저장 슬롯; `ldrd r2, r3` + `vmov d7, r2, r3`(코어 레지스터를 거친 double, 합류점의 phi까지)를 64비트 값으로; ARM32 스택 매개변수(double은 두 워드). `floats.c` ARM/Thumb -O0/-O2 재컴파일(qemu-arm) 비트 단위 일치. 공통: 피호출 함수의 매개변수(live-in)를 최적화한 SSA에서(술어 실행 `movgt/movle`이 남기던 가짜 `r0` 매개변수, `sc_or(v2, 2, 0x402024)` 같은 가짜 인자 제거), `-fipa-ra`로 호출 너머 결과 레지스터를 유지하는 호출자도 결과를 읽는 것으로
- [x] README 스크린샷과 사용 흐름·디버거 따라 하기(`docs/screenshots/make_screenshots.py`로 재생성)
- [x] 비트필드 쓰기: 저장 단위의 읽기-수정-쓰기(`unit = unit & keep | (x & m) << k | c`, 앞서 읽어 둔 단위 값·바이트 하나만 쓰는 저장·단위가 겹치는 컨테이너 포함)를 필드마다 대입 `p->ihl = x; p->version = 4;`로 — 지키는 비트가 정확히 다른 필드일 때만, 앞서 읽은 값이면 그 사이에 같은 바이트를 바꾸는 저장이 없을 때만; 그 저장에만 쓰인 단위 읽기는 숨김. `types.c` `packet_set` -O0/-O2 재컴파일 비교
- [x] 프로젝트 스냅숏과 병합(`relic/analysis/project.py`): 모든 주석 상태(이름·주석·변수 이름·타입·구조체·북마크·C 타입)의 이름 붙인 사본을 프로젝트 파일에 저장, 복원은 undo 한 단계; 같은 바이너리(프로젝트에 SHA-256 기록)의 다른 프로젝트 파일 병합 — 없는 것은 추가, 서로 다른 값은 충돌로 보고하고 우리 값(`--theirs`면 그쪽 값) 유지, 다른 바이너리의 프로젝트는 거부(`--force`), 패치는 병합하지 않음. `relic project`, File ▸ Snapshots / Merge project, 스크립팅 `snapshot()`/`restore_snapshot()`/`merge()`
- [x] ARM·AArch64 라이브러리 시그니처: Thumb 함수 심볼(주소 bit 0)의 코드를 1바이트 밀려 읽던 버그(ARM 정적 바이너리에서 584개 중 2개 → 375개 이름), 재배치가 채우는 즉치 비트만 가리는 비트 단위 마스크(`adrp`·lo12·`b`/`bl`·조건 분기·`movw`/`movt`, `bl` → `blx` 변환 비트 포함; GOT·TLS·정의 없는 weak 호출(`nop`으로 바뀜)은 워드 전체), 부분 마스크를 담는 시그니처 파일 형식(이전 파일 호환); 일치 판정: 고정 바이트 64 이상이면 함수 끝 확인 생략(아직 noreturn을 모르는 호출로 분석이 다음 함수까지 이어진 경우), 더 긴 후보가 모두 참조로 부정되면 짧은 후보로. 정답 심볼과 비교: x86-64 582 → 640, AArch64 426 → 475, ARM 2 → 375(나머지 차이는 별칭). AArch64 `_start`가 넘기는 `__wrap_main`(`nop; b main`)을 따라가 `main` 찾기
- [x] MIPS·RISC-V 라이브러리 시그니처: 비트 단위 재배치 마스크(MIPS 26비트 점프·16비트 즉치, `R_MIPS_JALR`은 워드 전체; RISC-V U/I/S/B/J 즉치·완화되지 않은 `call`·압축 분기), RISC-V는 `R_RISCV_RELAX`/`R_RISCV_ALIGN` 위치(링커가 `auipc+jalr`을 `jal`로 줄이거나 nop을 지워 뒤 코드가 밀림)에서 패턴을 끊은 접두 시그니처(함수 끝 확인 없음, 알려진 바이트 32 이상 — 비슷한 프롤로그의 오탐 방지). 정답 심볼과 비교: RISC-V 107 → 202(오탐 0), MIPS 409 → 411
- [x] 디버거 힙 뷰(`relic/debugger/heap.py`, Heap 패널): libc 심볼 없이 `[heap]` 매핑의 청크를 처음부터 top까지 걷기(크기·플래그, 다음 청크의 PREV_INUSE로 해제 판정, 깨진 크기에서 멈추고 알림), 첫 청크 `tcache_perthread_struct`의 목록(counts uint16/uint8 판별, safe-linking(glibc 2.32+) 여부를 목록이 힙 안에 머무는 쪽으로 판별, 힙 밖 포인터·순환에서 멈춤)으로 tcache 청크 표시; 청크·목록 항목 더블클릭 → 메모리 뷰. `Session.heap()`. 합성 힙 바이트와 실제 프로세스(`tests/src/heap.c`: 사용 중·tcache 2개 목록·unsorted 해제 청크)로 테스트
- [x] 숫자 표시 형식(IDA H/R/B/O, `relic/numfmt.py`): 리스팅은 명령의 피연산자별(커서가 있는 피연산자, `[]` 안의 쉼표는 구분 아님, ARM `#`·AT&T `$` 접두사 유지), 의사 코드는 함수의 상수별(보이는 값 기준: 음수로 보이는 상수는 음수 키)로 16진·10진·문자 상수(`'ABCD'`, 출력 불가 바이트면 그대로)·2진·오프셋(주소의 이름); H는 16진↔10진 전환, 같은 형식을 다시 누르면 원래대로. 프로젝트 저장(`operands`, `numbers`)·undo·스냅숏·병합 포함, Edit ▸ Number 메뉴, 스크립팅 `op_format()`·`number_format()`
- [x] 반복 주석(Edit ▸ Repeatable comment, `:`): 그 주소와, 그 주소로 분기·호출하거나 참조하는 모든 명령에 `⇢ 주석`으로 표시(프로젝트 `repeatable`, undo·스냅숏·병합); Names 창(함수·import·라이브러리 함수·데이터 심볼·사용자 라벨, 필터, 더블클릭 이동, 이름 변경을 따라감), `Analysis.names()`, 스크립팅 `rcomment()`·`names()`
- [x] 호출 그래프(View ▸ Call graph, `Ctrl+Shift+G`, `relic/analysis/callgraph.py`): 커서가 있는 함수의 호출자(왼쪽)·피호출자(오른쪽)를 1–4단계까지(꼬리 호출 포함, 단계당 40개 넘으면 `…`), 더블클릭 이동, Shift+더블클릭은 그 함수를 중심으로 다시 그림
- [x] 내비게이션 밴드(창 위쪽 띠, `relic/analysis/navband.py`): 적재된 섹션 전체를 이어 붙여 함수 코드·라이브러리 코드·import 스텁(`.plt*`)·데이터·미분석 코드(어느 함수 블록에도 속하지 않은 실행 바이트)로 칠함, 현재 위치 표시, 클릭·드래그로 이동
- [x] 함수 밖 메모리 리스팅과 코드·데이터 정의(`relic/datalist.py`): 데이터 섹션·함수 사이의 실행 바이트를 리스팅으로(16진 뷰 대신) — 이름·xref 라벨(`unk_…`), 자동 문자열·이름 있는 곳을 가리키는 포인터(`dq offset name`)·0 반복(`dup(0)`)·바이트; 사용자 정의(U 정의 해제/원시 바이트, C 코드로 디스어셈블, D 바이트→워드→더블워드→쿼드워드, A 문자열, `*` 배열), 함수 만들기(P)·지우기(Ctrl+Delete: 분석을 다시 하고 프로젝트 `function_edits`에 저장, undo도 다시 분석). 이로써 대화형 UI 기준 항목을 모두 갖춰 README 진행률 100%
- [x] Lumina 대응 함수 메타데이터 공유(`relic/analysis/lumina.py`): 명령의 니모닉·피연산자에서 주소·분기 대상(블록 번호)·pc/rip 상대 변위를 지운 위치 독립 지문(명령 6개 미만은 제외), 함수 이름(사용자·심볼, 시그니처 추정은 제외)·주석(함수 시작 기준 오프셋)·반복 주석·변수 이름·타입을 저장소에 push, 같은 지문의 함수에 pull(사용자가 이름 붙인 함수는 `--overwrite` 없이는 그대로, undo 한 단계); 저장소는 JSON 파일(`~/.relic/lumina.json`, `$RELIC_LUMINA`) 또는 `relic lumina serve`(기본 localhost) HTTP 서버. stripped 사본에 13개 함수 이름이 정확히 붙음. File ▸ Lumina, 스크립팅. 버전 기록(Teams 대응): commit(작성자·메시지)·log·diff(버전↔버전·버전↔현재, 항목별 추가/삭제/변경)·checkout(undo 한 단계), `relic project commit|log|diff|checkout`, File ▸ History. 프로젝트·협업 영역 README 100%
- [x] 스크립팅·확장: 확장점(`relic/extend.py` — 플러그인 파일 로더(내장 ELF/PE/raw보다 먼저), 프로세서 모듈(`decode(code, addr) -> Insn`, 분석이 분기·호출을 따라감), 의사 코드 훅(줄 바꾸기, 실패한 훅은 건너뜀)), CLI도 플러그인을 읽음(확장점만), 플러그인 훅 `on_edit`·`on_debug_stop`, 스크립트 파일 실행(File ▸ Run script `Alt+F7`, 최근 목록, 출력·오류는 Python 콘솔), API 추가(`read`·`read_int`·`sections`·`insn`·`define`·`undefine`·`make_function`·`delete_function`·`bookmark`·`callers`·`callees`), 모든 API에 docstring, `docs/scripting.md` 자동 생성(`tools/gen_scripting_docs.py`, 최신 여부 테스트). 스크립팅·확장 영역 README 100%
- [x] 타입 라이브러리와 호출을 통한 타입 전파(`relic/decompiler/typelibs.py`): libc 구조체(`stat`은 x86-64와 asm-generic 레이아웃 따로), `Analysis.load_type_library`, `relic types FILE --lib libc`, C types 창의 Load libc types; 원형의 구조체 포인터 결과가 접근으로 짐작한 `int *`보다 우선(`v = localtime(&t)` → `struct tm *v; v->tm_year`, 식 안에 접힌 호출의 결과도), 주소가 `struct S *` 인자로 넘어가는 스택 슬롯은 `struct S` 지역 변수(안쪽 슬롯은 `.st_size` 필드), 사용자가 타입을 준 함수의 매개변수·반환 타입이 호출자의 인자 변수로
- [x] Windows API 타입 라이브러리(`relic/decompiler/win32_h.py`): kernel32·advapi32·user32·ws2_32 함수 원형 175개(`sigs.lookup`의 내장 원형: 가져오지 않아도 인자 수·타입·결과 타입), `win32` 타입 라이브러리(HANDLE·DWORD 등 typedef와 `SYSTEM_INFO`·`STARTUPINFOA`·`PROCESS_INFORMATION`·`WIN32_FIND_DATAA`·`MEMORY_BASIC_INFORMATION`·`CRITICAL_SECTION`·`MSG` 등 구조체 18개, 32/64비트 레이아웃을 mingw `<windows.h>`의 `offsetof`로 검증), PE면 기본 라이브러리(`load_type_library()`, C types 창의 Load type library); Win64에서 원형의 5번째 이후 인자를 스택(홈 영역 다음)에서 읽음(`CreateFileA` 7개), 64비트 대상에서 32비트 스택 인자 저장을 쪼개진 double로 오인하던 문제 수정, 스택 구조체의 첫 필드 접근도 필드로(`st.wYear`)
- [x] `ccr-1ba61b91-3k0qem` 브랜치(PR #14에서 갈라져 같은 기능을 따로 만든 줄기)와 비교해 main에 없던 것을 옮김: IR 순회 가속(`children`은 정확한 타입의 사전, `transform`은 생성기·zip 없이, `walk`는 명시적 스택 — gzip 앞 60개 함수 22.3초 → 19.5초, 출력 동일), 정적 MIPS의 `$gp`를 `.reginfo`(`ri_gp_value`)에서(문자열 참조 10 → 401/1241, 점프 테이블 0 → 45), MIPS branch-likely(`beql`·`bnel` …: 지연 슬롯의 쓰기를 조건부 `x = c ? new : x`로, 손으로 쓴 `bnel` 함수의 의사 코드를 호스트에서 컴파일해 결과 비교), 따옴표 문자열 패치(`--bytes '"/bin/ls\0"'`, GUI 패치 창도), 64비트 주소를 나르는 Qt 시그널을 `object`로(PE64 주소 0x140001000이 0x40001000으로 잘려 이동하던 버그, 레지스터 편집 창의 64비트 값), 응답에 번호가 없는 watchpoint는 `DebugError`, 쓰이지 않던 `decode_block`·`has_load`·`_defs` 래퍼 제거. 옮기지 않은 것(main 쪽이 이미 같거나 더 나음): 디버거 watchpoint·레지스터 편집, ruff, MIPS GOT·점프 테이블·리프터 구조, 나눗셈 복원, 패치·콘솔. 일반 if-conversion은 테스트 2개를 깨고 읽기 좋은 `if`를 삼항식으로 바꿔 보류
