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

- [ ] **P0** GitHub Actions CI (pytest, gcc 설치)
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

- [ ] **P1** 단계 1 — IR 정의와 x86-64 리프팅
- [ ] **P1** 단계 2 — SSA, 상수/복사 전파, 죽은 코드 제거
- [ ] **P1** 단계 3 — 호출 인자/반환값 복원, 스택 변수
- [ ] **P1** 단계 4 — 제어 흐름 구조화(if/while/switch)
- [ ] **P2** 단계 5 — 타입 추론, C 출력 정리
- [ ] **P2** 단계 6 — GUI 디컴파일 뷰, 다른 아키텍처 리프터

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
