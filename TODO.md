# TODO

남은 작업만 적습니다. 끝난 일의 기록은 [docs/history.md](docs/history.md)에 있습니다.

우선순위: **P0** 지금 하는 일 / **P1** 다음 / **P2** 여유 있을 때.
모든 항목은 테스트(가능하면 재컴파일·실행 비교)와 함께 끝냅니다.

## P0 — 디컴파일러 속도

실제 바이너리에서 의사 코드가 느리면 GUI의 Pseudocode 탭이 기다리게 됩니다.

- [x] 측정 도구: `tools/bench.py` — 분석·전체 디컴파일 시간, 함수별 상위 시간(함수당 시간 상한), goto·미해결 점프·`__asm` 수
- [x] `/usr/bin/grep`: 174개 함수 디컴파일 87.3초 → 43초대(goto 1723, 미해결 점프 8, `__asm` 18 그대로). 단독으로 처음 여는 경우 `main` 89초 → 27초, `sub_95b0` 32초 → 9초. 한 일: 필드 접근이 있는 매개변수만 호출자 조회, `narrow` 한 번의 순회(고정점 반복), DCE 사용 횟수 1회 계산 후 증감, 호출자 구조체 함수당 1회 생성, 피호출자가 요청한 호출자 구조체는 그 피호출자의 접근만 병합
- [ ] 남은 비용: 구조체 스캔이 관련 함수마다 전체 `decompile_ir`(lift→SSA→최적화→호출 복원)를 요구 — 큰 함수는 자기 피호출자들까지 준비. `_rewrite`/`transform`(최적화 반복마다 전체 재작성)과 `_compute_livein`(호출마다 피호출자 SSA)이 다음 후보
- [x] 함수 하나가 오래 걸려도 GUI가 기다리지 않음: 다른 함수로 이동하면 실행 중인 디컴파일을 취소(취소 결과는 캐시하지 않음), 취소가 구조체·반환 폭 캐시의 재귀 가드를 "없음"으로 남기지 않음

## P1 — 출력 품질

- [x] libc 인자·결과 타입으로 매개변수·변수 타입 지정(`strlen(a1)` → `char *a1`, `malloc(n)` → `size_t n`, `void *` 결과, `fopen` → `FILE *`, 상수 형식 문자열의 `%s`/`%p`/`%zu`, 식 안의 호출 포함) — 메모리 접근으로 복원한 포인터 타입이 우선
- [ ] goto 줄이기 — 기준선(bench): true 153, cat 375, gzip 911, grep 1861. 구조화·출력 정확성은 무작위 CFG 실행 비교 테스트(`test_random_cfgs_run_like_the_cfg`: 구조화 트리, `test_emitted_c_runs_like_the_cfg`: 출력한 C를 gcc로 컴파일해 실행)로 지킴: 줄이는 변경도 이 테스트를 통과해야 함
  - [ ] -O0 비교 트리(범위 검사 분기마다 꼬리 블록이 복제된 형태)를 switch로
  - [ ] 큰 상태 기계 함수의 goto(gnulib `quotearg`, gzip deflate/inflate) — 조건 기반 구조화 검토
- [x] 함수 내부 데이터를 리스팅에 데이터로 표시: ARM 리터럴 풀(`ldr r0, [pc, #n]`, AArch64 `ldr x0, #addr`)은 `.word` + 값·참조, Thumb `tbb`/`tbh`·ARM `ldr pc` 점프 테이블은 항목마다 대상 레이블

## P1 — 분석

- [x] 정적 링크된 stripped 바이너리의 라이브러리 함수 이름 찾기(시그니처) — `relic/analysis/libsigs.py`, `relic sigs build`, File ▸ Apply library signatures
  - [ ] 남은 일: 코드가 같은 짧은 스텁(`__chk_fail`/`__fortify_fail` 류) 구분, libgcc·libstdc++ 시그니처, 다른 아키텍처(ARM/AArch64/MIPS 재배치 마스크 확인)
- [x] capstone 일괄 디코딩: 캐시에 없을 때 x86 명령 8개까지 한 번에 디코딩해 캐시(정적 바이너리 분석 약 9% 단축). 남은 비용은 capstone 파이썬 바인딩의 명령당 객체·detail 생성(약 70µs) — detail 없이(`disasm_lite`) 디코딩하고 필요할 때만 detail을 만드는 방법은 명령의 약 37%에만 해당해 보류

## P2

- [ ] 플러그인 훅: 리스팅 줄 꾸미기(주석·색), 분석 완료 이벤트
- [ ] 열거형·공용체 타입
- [ ] RISC-V / PPC 리프터(호출 인자 추출은 같은 경로로), PPC64 ELFv1 함수 디스크립터, RISC-V `auipc` 쌍
- [ ] ARM 데이터 영역을 코드로 잘못 읽은 경우(coprocessor 명령 등) 감지
