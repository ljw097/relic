# TODO

우선순위: **P0** 다음 작업 / **P1** 중요 / **P2** 여유 있을 때

## GUI

- [x] 커서 아래 단어 하이라이트 (리스팅·의사 코드, 레지스터는 rax/eax/ax/al 별칭까지)
- [x] 최근 파일 목록(File ▸ Open Recent), 창 크기·dock 배치 저장 (`QSettings`, `RELIC_SETTINGS`로 ini 경로 지정 가능)
- [x] 백그라운드 작업 취소·진행 표시: 상태 표시줄 진행 막대 + Cancel(`Ctrl+.`), 스레드별 취소 토큰(`relic/progress.py`)을 함수 탐색·xref·취약점 스캔·디컴파일 패스 사이에서 확인; 종료 시 기다리지 않고 취소(최대 2초, 넘으면 창을 숨기고 스레드 종료 후 닫음)
- [x] 취약점 스캔 실패를 "발견 없음"과 구분해 표시(`VulnsThread.failed`, 표에 오류 행)
- [x] CFG 레이아웃: Sugiyama 방식(`relic/gui/layout.py`) — back edge 역전, 최장 경로 층, 긴 간선 더미 노드 경로, barycenter 교차 최소화(`/bin/ls` 큰 함수 교차 16656 → 1248), isotonic 좌표 배치, 층 하단까지 수직으로 내린 뒤 꺾는 간선
- [ ] **P2** CFG: 노드 수천 개 함수에서 교차 계산(층 쌍마다 O(E²)) 가속, 간선 묶음(bundling), 접기
- [ ] **P2** 테마 전환(라이트/다크), 폰트 크기 설정

## 아키텍처별 분석 보강

현재 함수 탐색은 모든 아키텍처에서 동작하지만, 아래 항목은 x86-64에서만 동작한다.

- [ ] **P0** 함수 단위 레지스터 상수 전파 패스 (공통 기반)
  - x86-32 PIC: `__x86.get_pc_thunk.*` + `add` 로 만든 GOT 기준 레지스터
  - AArch64: `adrp` + `add` / `ldr`
  - ARM: 리터럴 풀 `ldr rN, [pc, #off]`, `add rN, pc, rN`
  - MIPS: `lui` + `addiu`, `$gp` 기준 접근
- [ ] **P0** 호출 규약별 인자 추출을 `vulns`에서 공통 사용
  - [x] x64 SysV / Win64, x86 cdecl: 디컴파일러가 복원한 호출 인자 사용 (x64는 블록 안 역추적으로 결론이 안 날 때만; GUI는 창을 먼저 띄우고 백그라운드에서 스캔)
  - [x] AArch64 x0–x7 (AArch64 리프터)
  - [x] ARM r0–r3 (ARM32 리프터)
  - [ ] MIPS a0–a3, RISC-V a0–a7, PPC r3–r10 (해당 리프터가 생기면 같은 경로로)
- [x] **P1** 점프 테이블: ~~x86-32 PIC(GOT 기준 오프셋)~~ (완료), ~~AArch64(`adrp`+`add` 테이블, `ldrb/ldrh/ldr` 항목, `adr` 기준, `add ..., sxtb #2`, 다른 블록의 `cmp`와 `mov` 별칭으로 범위)~~ (완료), ~~ARM(`addls pc, pc, rN, lsl #2`, `ldr pc, [pc, rN, lsl #2]`, Thumb `tbb`/`tbh`, `adr`+`ldr`+`add`+`bx` 오프셋 테이블)~~ (완료)
  - 상대 테이블은 후보 기준 주소들을 검증해서 선택
- [ ] **P1** MIPS: `.MIPS.stubs` / GOT(`DT_MIPS_GOTSYM`, `DT_MIPS_LOCAL_GOTNO`) 기반 import 이름 해석, 지연 슬롯을 블록에 포함
- [x] **P1** ARM Thumb 모드: 주소별 명령어 집합(`$a`/`$t` 매핑 심볼, 심볼·엔트리 LSB, `bl`은 유지·`blx label`은 전환), IT 블록(조건을 한 번에 디코딩), Thumb PLT 진입점(`bx pc`)
  - [x] 심볼 없는(stripped) ARM / Thumb / AArch64: `_start`의 리프트된 IR에서 `__libc_start_main` 첫 인자(GOT·리터럴 풀 슬롯)를 읽어 `main` 복원, 함수 사이 빈 구간의 프롤로그 스캔(A32/Thumb `push {…, lr}`, AArch64 `stp x29, x30`·`paciasp`·`bti c`)으로 포인터로만 쓰이는 함수(`win`) 발견
  - [ ] **P2** 데이터 영역 오디코딩(ldc/stc 같은 coprocessor 명령) 감지
- [ ] **P2** PPC64 ELFv1 함수 디스크립터, RISC-V `auipc` 쌍

## 테스트 / 인프라

- [x] **P0** GitHub Actions CI (pytest, gcc 설치, Python 3.10 / 3.12 / 3.13)
- [ ] **P1** 멀티 아키텍처 샘플: `-m32`(완료: vuln32·flow32, CI에 gcc-multilib), `aarch64-linux-gnu-gcc`(완료: vuln_a64·flow_a64), `arm-linux-gnueabihf-gcc`(완료: vuln_arm·vuln_thumb·flow_arm·flow_thumb; CI는 교차 컴파일 job이 샘플을 만들고 본 job이 `-m32`로 재컴파일 검증), `mipsel-linux-gnu-gcc` (툴체인 없으면 skip)
- [x] case마다 함수를 호출하는 `switch` 샘플(`flow.c`의 `sw_calls`): x86-64/x86-32 × -O0/-O2 모두 점프 테이블 → `switch`, 재컴파일 검증
- [x] PE 테스트: MinGW x64/x86 샘플로 로더·COFF 심볼·IAT 호출 이름·checksec·vulns·디컴파일 (CI에 mingw 설치, 없으면 skip)
- [ ] **P2** ruff 린트 / 포맷 설정

## 분석 정확도

- [x] C++ 심볼 디맹글링(`relic/demangle.py`: libstdc++ `__cxa_demangle`, 없으면 `c++filt`): 목록·리스팅은 전체 이름, 의사 코드 호출은 `ns::Cls::method`, 이름 해석은 원래·전체·짧은 이름 모두
- [x] PE: 예외 디렉터리(`.pdata`)로 함수 시작 시드(chained 항목 제외), TLS 콜백 이름(`tls_callback_N`) — stripped MinGW x64에서 함수 130 → 174개
- [ ] **P2** 함수 내부 데이터(점프 테이블, 리터럴 풀)를 코드로 오인하지 않도록 표시
- [ ] **P2** 대형 바이너리 성능 측정 및 디코딩 캐시 개선

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
  - [ ] **P2** if-else-if 사슬 → switch
  - [x] `-O2` goto 줄이기 1차: 단락 평가 `&&`/`||` 결합, 후지배자 없는 if의 합류점 선택, 작은 비순환 꼬리 영역 복제(6블록/12문장) — `/usr/bin/{true,cat,gzip}` goto 1911 → 1469
  - [ ] **P2** 남은 goto는 대부분 370–480블록 상태 기계 함수(gnulib `quotearg`, gzip deflate/inflate)에 몰려 있음 — 조건 기반 구조화(DREAM 계열) 검토
  - [x] 상수 나눗셈·나머지 복원(`arith.py`): 매직 넘버 곱셈 → `x / c`, `x % c`, 곱셈 역원 비교 → `x % c == r` (부호·음수 제수·64비트, 평가로 검증)
  - [x] 부호 있는 2의 거듭제곱 나눗셈·나머지(`(x < 0 ? x + 15 : x) >> 4` → `x / 16`, `% 8`)
- [x] **P1** 단계 5 — out-of-SSA, 타입, C 출력 (`outssa.py`, `vartypes.py`, `pipeline.py`, `emit.py`)
  - [x] phi → 복사 + 간섭 기반 병합(인터프리터로 검증), 단일 사용 임시 변수 인라인
  - [x] void / 반환 폭(호출자가 읽는 폭), 변수 폭 축소(`low32` 제거), 포인터·unsigned 추론, 복사로 포인터 타입 전파
  - [x] 시그니처·지역 변수 선언, 문자열·심볼·배열 인덱스, 포인터 산술 원소 단위, `&&` 조건, else-if, early return
  - [x] 줄 ↔ 주소 매핑(`Decompiled.lines`, `relic decompile --addrs`)
  - [x] 재컴파일 테스트: `checksum`/`classify` 디컴파일 결과를 gcc로 다시 컴파일해 원본과 비교
  - [x] 사용자 이름 변경(`Analysis.renames`)·주석·변수 이름(`Analysis.var_names`)을 의사 코드에 반영
  - [ ] **P2** 구조체 필드 복원(`notes[i]->size` 대신 `*(int *)(notes[i] + 8)`), libc 인자 타입으로 매개변수 타입 지정
  - [ ] **P2** 대형 바이너리 성능: `/usr/bin/grep` 168개 함수 71초 — 함수 단위 지연 디컴파일 결과 캐시, `_count_uses` 증분화
- [ ] **P1** 단계 6 — GUI 디컴파일 뷰, 다른 아키텍처
  - [x] GUI Pseudocode 탭(`Tab`/`F5`): 지연 디컴파일·캐시, 리스팅과 커서 주소 동기화, 이름 변경 반영, 더블클릭 이동
  - [x] 디컴파일은 백그라운드 스레드에서(한 번에 하나, 진행 중 표시, 오래된 결과 폐기)
  - [x] 의사 코드에서 변수·매개변수 이름 변경(`N`, 프로젝트 파일에 저장), 사용자 주석 표시
  - [x] AArch64 리프터(`lift/arm64.py`): 시프트·확장 피연산자, pre/post-index, ldp/stp, csel/cset/ccmp, 비트필드, cbz/tbz, NZCV(C=no-borrow); AAPCS64, `__stack_chk_guard` 카나리, `adrp` 페이지를 코드 참조로 오인하지 않음
  - [x] ARM32 리프터(`lift/arm.py`): A32·Thumb-2, 조건 실행(`movgt` → `c ? new : old`, 조건부 호출/리턴은 합성 블록), 배럴 시프터 캐리, 리터럴 풀 상수, ldm/stm/push/pop, `__aeabi_idiv(mod)` → `/`·`%`, cbz/cbnz, strex; AAPCS(r0–r3), 정렬용 `push {r3, lr}` 숨김, ARM PLT 스텁 해석
  - [x] 공통 개선(ARM에서 발견): 루프에서 스택 버퍼를 훑는 포인터 phi를 고정 스택 주소로 잘못 보던 버그 수정, 조건 플래그 중복 전파(술어 실행), `c ? x : !c` 류 정리, 단독 GOT 슬롯 → `&stdout`
  - [x] AArch64 점프 테이블(`flow.c`의 12-case `sw_big`, 모든 아키텍처에서 재컴파일 검증)
  - [x] 호출 간 레지스터 보존(gcc `-fipa-ra`): 바이너리 안 함수 호출은 피호출 함수가 (전이적으로) 쓰는 레지스터만 덮어쓴다고 보고(`decompiler/clobbers.py`), import·간접 호출·미해결 점프·syscall은 ABI 전체. 이전에는 `gcd(y, 4) - sc_or(y, 9)`가 `sc_or(gcd(y, 4), 9)`와 미정의 변수로 나왔음
  - [x] 32비트 `int` 매개변수에 넘기는 음수 상수: 피호출 함수가 인자 레지스터를 하위 32비트로만 읽으면 `0xfffffffb` 대신 `-5`
  - [x] x86-32: cdecl 스택 인자, 스택 매개변수(`a1`…), PC 썽크(`__x86.get_pc_thunk.*`, stripped는 본문으로 인식), `main`의 스택 재정렬, GOT 경유 전역(`stdout`)

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
