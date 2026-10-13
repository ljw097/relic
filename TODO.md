# TODO

우선순위: **P0** 다음 작업 / **P1** 중요 / **P2** 여유 있을 때

## GUI

- [ ] **P1** 디스어셈블리 뷰에서 커서 아래 단어(레지스터·심볼) 하이라이트
- [ ] **P1** 최근 파일 목록, 창 배치(dock 상태) 저장
- [ ] **P2** 테마 전환(라이트/다크), 폰트 크기 설정

## 아키텍처별 분석 보강

현재 함수 탐색은 모든 아키텍처에서 동작하지만, 아래 항목은 x86-64에서만 동작한다.

- [ ] **P0** 함수 단위 레지스터 상수 전파 패스 (공통 기반)
  - x86-32 PIC: `__x86.get_pc_thunk.*` + `add` 로 만든 GOT 기준 레지스터
  - AArch64: `adrp` + `add` / `ldr`
  - ARM: 리터럴 풀 `ldr rN, [pc, #off]`, `add rN, pc, rN`
  - MIPS: `lui` + `addiu`, `$gp` 기준 접근
- [ ] **P0** 호출 규약별 인자 추출을 `vulns`에서 공통 사용
  - x64 SysV / Win64, x86 cdecl(스택 `push`, `mov [esp+N]`), AArch64 x0–x7, ARM r0–r3, MIPS a0–a3, RISC-V a0–a7, PPC r3–r10
- [ ] **P1** 점프 테이블: x86-32 PIC(GOT 기준 오프셋), AArch64(`ldrb/ldrh` + `adr` + `add ..., lsl`), ARM(`ldrls pc, [pc, rN, lsl #2]`)
  - 상대 테이블은 후보 기준 주소들을 검증해서 선택
- [ ] **P1** MIPS: `.MIPS.stubs` / GOT(`DT_MIPS_GOTSYM`, `DT_MIPS_LOCAL_GOTNO`) 기반 import 이름 해석, 지연 슬롯을 블록에 포함
- [ ] **P1** ARM Thumb 모드 (심볼 LSB, `blx` 모드 전환)
- [ ] **P2** PPC64 ELFv1 함수 디스크립터, RISC-V `auipc` 쌍

## 테스트 / 인프라

- [x] **P0** GitHub Actions CI (pytest, gcc 설치, Python 3.10 / 3.12 / 3.13)
- [ ] **P1** 멀티 아키텍처 샘플: `-m32`, `aarch64-linux-gnu-gcc`, `arm-linux-gnueabi-gcc`, `mipsel-linux-gnu-gcc` (툴체인 없으면 skip)
- [ ] **P1** case마다 함수를 호출하는 `switch` 샘플 추가 — 지금 `classify`는 `-O2`에서 값 배열 조회로 바뀌어 점프 테이블 테스트가 안 됨
- [ ] **P1** PE 테스트: 로더, IAT 호출 이름 해석, checksec (mingw 또는 커밋된 작은 샘플)
- [ ] **P2** ruff 린트 / 포맷 설정

## 분석 정확도

- [ ] **P1** C++ 심볼 디맹글링
- [ ] **P1** PE: 예외 디렉터리(`.pdata`)로 함수 시작 시드, TLS 콜백
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
  - [ ] **P2** 루프 유도 변수 → `for`, if-else-if 사슬 → switch
  - [ ] **P2** `-O2` 대형 함수의 goto 줄이기 (노드 복제 확대, 조건 기반 구조화) — `/usr/bin/grep` 168개 함수에서 goto 3020개
- [x] **P1** 단계 5 — out-of-SSA, 타입, C 출력 (`outssa.py`, `vartypes.py`, `pipeline.py`, `emit.py`)
  - [x] phi → 복사 + 간섭 기반 병합(인터프리터로 검증), 단일 사용 임시 변수 인라인
  - [x] void / 반환 폭(호출자가 읽는 폭), 변수 폭 축소(`low32` 제거), 포인터·unsigned 추론, 복사로 포인터 타입 전파
  - [x] 시그니처·지역 변수 선언, 문자열·심볼·배열 인덱스, 포인터 산술 원소 단위, `&&` 조건, else-if, early return
  - [x] 줄 ↔ 주소 매핑(`Decompiled.lines`, `relic decompile --addrs`)
  - [x] 재컴파일 테스트: `checksum`/`classify` 디컴파일 결과를 gcc로 다시 컴파일해 원본과 비교
  - [ ] **P1** 사용자 이름 변경(`Analysis.renames`)·주석을 의사 코드에 반영, 변수 이름 변경
  - [ ] **P2** 구조체 필드 복원(`notes[i]->size` 대신 `*(int *)(notes[i] + 8)`), libc 인자 타입으로 매개변수 타입 지정
  - [ ] **P2** 대형 바이너리 성능: `/usr/bin/grep` 168개 함수 71초 — 함수 단위 지연 디컴파일 결과 캐시, `_count_uses` 증분화
- [ ] **P1** 단계 6 — GUI 디컴파일 뷰(디스어셈블리와 동기화), x86-32 리프터·cdecl 스택 인자

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
