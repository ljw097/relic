# TODO

우선순위: **P0** 다음 작업 / **P1** 중요 / **P2** 여유 있을 때

## GUI

- [x] 커서 아래 단어 하이라이트 (리스팅·의사 코드, 레지스터는 rax/eax/ax/al 별칭까지)
- [x] 최근 파일 목록(File ▸ Open Recent), 창 크기·dock 배치 저장 (`QSettings`, `RELIC_SETTINGS`로 ini 경로 지정 가능)
- [x] 백그라운드 작업 취소·진행 표시: 상태 표시줄 진행 막대 + Cancel(`Ctrl+.`), 스레드별 취소 토큰(`relic/progress.py`)을 함수 탐색·xref·취약점 스캔·디컴파일 패스 사이에서 확인; 종료 시 기다리지 않고 취소(최대 2초, 넘으면 창을 숨기고 스레드 종료 후 닫음)
- [x] 취약점 스캔 실패를 "발견 없음"과 구분해 표시(`VulnsThread.failed`, 표에 오류 행)
- [x] CFG 레이아웃: Sugiyama 방식(`relic/gui/layout.py`) — back edge 역전, 최장 경로 층, 긴 간선 더미 노드 경로, barycenter 교차 최소화(`/bin/ls` 큰 함수 교차 16656 → 1248), isotonic 좌표 배치, 층 하단까지 수직으로 내린 뒤 꺾는 간선
- [x] CFG 교차 계산 가속: Fenwick 트리로 층 쌍마다 O(E log V) (3000-case switch 6000블록 2.0초 → 0.18초)
- [ ] **P2** CFG: 간선 묶음(bundling), 블록 접기
- [x] 테마 전환(라이트/다크, `Ctrl+Shift+L`)과 코드 글꼴 크기(`Ctrl+=`/`Ctrl+-`/`Ctrl+0`): 모든 뷰·표·앱 팔레트에 즉시 반영, `QSettings`에 저장

## 스크립팅

- [x] 스크립팅 API(`relic/scripting.py`), GUI Python 콘솔(`Ctrl+Shift+P`, 기록, 여러 줄 문장), 플러그인(`RELIC_PLUGINS` / `~/.relic/plugins`의 `register(api)` → Plugins 메뉴, 오류는 콘솔에), `relic script`
- [ ] **P2** 플러그인이 뷰에 주석·색을 다는 훅(리스팅 줄 꾸미기), 분석 완료 이벤트

## 패치

- [x] 바이트·NOP·조건 분기 반전(x86, ARM/Thumb, AArch64, MIPS)·어셈블(keystone), 재분석, 프로젝트에 저장·다시 적용, 패치된 파일 내보내기(`relic patch`, Edit 메뉴)
- [ ] **P2** 디버거가 패치된 이미지를 실행(지금은 디스크의 원본), 패치 undo 기록

## 디버거 (로컬, GDB/MI, pwndbg식 GUI)

- [x] GDB/MI 레코드 파서·프로세스 래퍼(`relic/debugger/mi.py`), 세션(`session.py`): pty 입출력, 시작(entry/main)·계속·단계 실행·커서까지·중단·종료, 중단점, PIE 슬라이드(`to_live`/`to_static`), 레지스터 변경 추적, `telescope`, 백트레이스
- [x] GUI(`relic/gui/debugger.py`): 작업 스레드 컨트롤러, Registers·Stack·Backtrace·Code·Console 패널, Debug 메뉴(F9/F7/F8/F4/F2), 리스팅 pc·중단점 표시
- [x] vmmap 패널, 메모리(hexdump) 뷰(주소·gdb 식·Relic 이름), 레지스터·스택 값 더블클릭으로 리스팅/메모리 따라가기
- [x] 중단점 목록 패널(조건·활성/비활성·적중 횟수, 재실행 시 유지)
- [x] 하드웨어 watchpoint(쓰기/읽기/접근, 바이너리 전역·주소는 PIE 보정한 `*(T *)live`로, 크기 1/2/4/8, 그 밖은 gdb 식), 이름으로 중단점(바이너리 함수·`puts@plt`는 정적 주소, `puts` 같은 라이브러리 함수는 gdb pending 중단점으로 libc 안에서 멈춤), 중단점 패널에 종류 열·`Delete`로 삭제, 멈춘 이유(`watchpoint 3 …: 0 -> 0x4052a0`) 표시
- [x] 의사 코드 뷰에서 현재 문장(pc)·중단점 줄 표시
- [x] 레지스터·메모리 값 편집(Registers 패널 `E`/우클릭, Debug ▸ Set register / Write memory: hex·`"문자열\n"`·`0x…` 워드)
- [ ] **P2** glibc 힙 정보(bins/chunks)

## 아키텍처별 분석 보강

- [x] **P0** 함수 단위 레지스터 상수 전파 패스(`analysis/constprop.py`): CFG 위 전방 데이터 흐름(합류점은 모든 선행자가 같은 값일 때만, 호출은 caller-saved 소멸), "주소" 플래그(pc 유래 값, 비-PIE 절대 리터럴)가 붙은 값만 데이터 참조로 기록 → 문자열·전역·GOT 슬롯 xref와 리스팅 주석
  - [x] x86-32 PIC: `__x86.get_pc_thunk.*` + `add` 로 만든 GOT 기준 레지스터
  - [x] AArch64: `adrp` + `add` / `ldr`
  - [x] ARM / Thumb: 리터럴 풀 `ldr rN, [pc, #off]`, `add rN, pc`, `adr`, `movw`/`movt`
  - [x] MIPS: `$gp` 고정(`_gp` = GOT + 0x7ff0), `lui` + `addiu`, GOT 슬롯 로드(PIE의 로컬 GOT 페이지 + `addiu`), 슬롯에서 읽은 `$t9`로 호출 이름
  - 문자열 xref 비율: armhf `ld.so` 1 → 513/842, aarch64 `ld.so` 0 → 409/836, `vuln32_pie` 0 → 10/10
  - [x] ARM/AArch64 즉치값은 주소로 보지 않음(`mov w0, #0xffff`가 PIE에서 함수 시작으로 잡히던 문제), 빈 구간 계산은 함수 범위가 아니라 블록 구간으로(멀리 떨어진 cold 블록이 사이 함수들을 가리던 문제), 구간 중간의 프롤로그도 종결 명령 뒤라면 인정
- [ ] **P0** 호출 규약별 인자 추출을 `vulns`에서 공통 사용
  - [x] x64 SysV / Win64, x86 cdecl: 디컴파일러가 복원한 호출 인자 사용 (x64는 블록 안 역추적으로 결론이 안 날 때만; GUI는 창을 먼저 띄우고 백그라운드에서 스캔)
  - [x] AArch64 x0–x7 (AArch64 리프터)
  - [x] ARM r0–r3 (ARM32 리프터)
  - [x] MIPS a0–a3 (MIPS32 리프터)
  - [ ] RISC-V a0–a7, PPC r3–r10 (해당 리프터가 생기면 같은 경로로)
- [x] **P1** 점프 테이블: ~~x86-32 PIC(GOT 기준 오프셋)~~ (완료), ~~AArch64(`adrp`+`add` 테이블, `ldrb/ldrh/ldr` 항목, `adr` 기준, `add ..., sxtb #2`, 다른 블록의 `cmp`와 `mov` 별칭으로 범위)~~ (완료), ~~ARM(`addls pc, pc, rN, lsl #2`, `ldr pc, [pc, rN, lsl #2]`, Thumb `tbb`/`tbh`, `adr`+`ldr`+`add`+`bx` 오프셋 테이블)~~ (완료)
  - 상대 테이블은 후보 기준 주소들을 검증해서 선택
- [x] **P1** MIPS: GOT(`DT_PLTGOT`, `DT_MIPS_LOCAL_GOTNO`, `DT_MIPS_GOTSYM`, `DT_MIPS_SYMTABNO`) 기반 import(슬롯·`.MIPS.stubs` 스텁), 지연 슬롯을 분기 블록에 포함(`Insn.delay`, `Block.last`는 분기), `bal`은 호출(`bal .+8`은 pc 읽기), `jalr $t9`는 `lw $t9, off($gp)` 슬롯으로 이름·noreturn 판정
- [x] **P1** ARM Thumb 모드: 주소별 명령어 집합(`$a`/`$t` 매핑 심볼, 심볼·엔트리 LSB, `bl`은 유지·`blx label`은 전환), IT 블록(조건을 한 번에 디코딩), Thumb PLT 진입점(`bx pc`)
  - [x] 심볼 없는(stripped) ARM / Thumb / AArch64: `_start`의 리프트된 IR에서 `__libc_start_main` 첫 인자(GOT·리터럴 풀 슬롯)를 읽어 `main` 복원, 함수 사이 빈 구간의 프롤로그 스캔(A32/Thumb `push {…, lr}`, AArch64 `stp x29, x30`·`paciasp`·`bti c`)으로 포인터로만 쓰이는 함수(`win`) 발견
  - [ ] **P2** 데이터 영역 오디코딩(ldc/stc 같은 coprocessor 명령) 감지
- [ ] **P2** PPC64 ELFv1 함수 디스크립터, RISC-V `auipc` 쌍

## 테스트 / 인프라

- [x] **P0** GitHub Actions CI (pytest, gcc 설치, Python 3.10 / 3.12 / 3.13)
- [ ] **P1** 멀티 아키텍처 샘플: `-m32`(완료: vuln32·flow32, CI에 gcc-multilib), `aarch64-linux-gnu-gcc`(완료: vuln_a64·flow_a64), `arm-linux-gnueabihf-gcc`(완료: vuln_arm·vuln_thumb·flow_arm·flow_thumb; CI는 교차 컴파일 job이 샘플을 만들고 본 job이 `-m32`로 재컴파일 검증), `mipsel-linux-gnu-gcc`(완료: vuln_mips·vuln_mips_pie·flow_mips, CI 교차 job에서 qemu로 재컴파일 검증)
- [x] case마다 함수를 호출하는 `switch` 샘플(`flow.c`의 `sw_calls`): x86-64/x86-32 × -O0/-O2 모두 점프 테이블 → `switch`, 재컴파일 검증
- [x] PE 테스트: MinGW x64/x86 샘플로 로더·COFF 심볼·IAT 호출 이름·checksec·vulns·디컴파일 (CI에 mingw 설치, 없으면 skip)
- [x] ruff 린트(`pyproject.toml`, E/F/W/B, CI `lint` job). 포맷터·import 정렬은 기존 줄바꿈 스타일과 맞지 않아 적용하지 않음

## 분석 정확도

- [x] C++ 심볼 디맹글링(`relic/demangle.py`: libstdc++ `__cxa_demangle`, 없으면 `c++filt`): 목록·리스팅은 전체 이름, 의사 코드 호출은 `ns::Cls::method`, 이름 해석은 원래·전체·짧은 이름 모두
- [x] PE: 예외 디렉터리(`.pdata`)로 함수 시작 시드(chained 항목 제외), TLS 콜백 이름(`tls_callback_N`) — stripped MinGW x64에서 함수 130 → 174개
- [ ] **P2** 함수 내부 데이터(점프 테이블, 리터럴 풀)를 코드로 오인하지 않도록 표시
- [x] 대형 바이너리 성능 1차: 빈 구간 스캔이 함수를 찾을 때마다 모든 블록 구간을 다시 정렬하던 것을 병합 구간 집합(`_Cover`)의 증분 갱신으로, `regs_access`는 처음 쓸 때 계산 — 정적 링크 vuln(1131 함수) 42초 → 17초
- [ ] **P2** 남은 시간의 대부분은 capstone 명령어 객체 생성(15만 개): 배치 디코딩이나 detail 없는 1차 디코딩 검토

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
  - [ ] **P2** -O0 비교 트리(범위 검사 분기마다 꼬리 블록이 복제된 형태)
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
  - [ ] **P2** libc 인자 타입으로 매개변수 타입 지정
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
  - [x] MIPS32 리프터(`lift/mips.py`, o32): 지연 슬롯은 분기 조건·호출 대상을 먼저 계산한 뒤 슬롯 명령, 그다음 분기(`lift_delayed`), `$gp`는 상수 `_gp`(쓰기·cprestore 저장 무시), 로컬 GOT 항목은 링크 시 상수, `jalr $t9`는 GOT 슬롯의 import 이름, hi/lo(mult/div), movn/movz, ext/ins; 점프 테이블(절대·`$gp` 상대 `.gpword`, `sltiu` 범위). 재컴파일 검증은 mipsel-gcc `-static` + `qemu-mipsel`
  - [x] 공통 개선(MIPS에서 발견): 스택 프레임의 반환 주소 슬롯은 x86 계열만(진입 sp+0은 호출자 영역: o32 인자 홈 슬롯 `arg_0`), 콜리 저장 레지스터 요약이 capstone `regs_access` 없는 아키텍처는 리프트 결과로, import GOT 슬롯을 통한 호출은 이름으로 출력, 가드 주소를 레지스터에 두는 카나리 인식, 분기형 부호 보정(`if (x < 0) x += 15`, 두 return)을 select로 바꿔 `/ 16`·`% 8` 복원, `sltiu x, 1` → `x == 0`
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
