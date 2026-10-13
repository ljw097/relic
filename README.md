# Relic

리버싱과 포너블을 위한 디스어셈블러 / 디컴파일러 (WIP).

현재는 **분석 엔진, CLI, GUI**와 x86-64 **디컴파일러**(`relic decompile`)가 동작합니다. GUI 디컴파일 뷰와 다른 아키텍처 리프터는 개발 중입니다.
진행 상황은 [TODO.md](TODO.md), 디컴파일러 설계는 [docs/decompiler-plan.md](docs/decompiler-plan.md)를 참고하세요.

## 기능

| 영역 | 상태 |
|---|---|
| 로더 | ELF / PE / RAW(셸코드·펌웨어 blob) |
| 디스어셈블 | capstone 기반: x86, x64, ARM, AArch64, MIPS, RISC-V, PPC |
| 함수 탐색 / CFG | 재귀 하강, noreturn 처리, tail call, x86-64 점프 테이블 복원 |
| stripped 바이너리 | `__libc_start_main` 인자로 `main` 복구, 프롤로그 스캔, `.init_array` 시드 |
| 참조 | 코드/데이터 xref, 문자열(ASCII, PE는 UTF-16LE) |
| checksec | ELF: RELRO / Canary / NX / PIE / FORTIFY / RPATH, PE: ASLR / DEP / CFG / SEH / GS |
| 포너블 휴리스틱 | `gets`·`strcpy` 등 위험 함수, 비상수 포맷 스트링, 폭 없는 `scanf("%s")`, ret2win 후보 |
| 프로젝트 | 이름 변경·주석·디컴파일러 변수 이름을 `<binary>.relic.json`에 저장 (CLI 출력에도 반영) |
| GUI | 함수 목록, 디스어셈블리 / CFG 그래프 / 의사 코드 / 헥스, xref·문자열·import·vulns·checksec 패널 |
| 디컴파일러 (x86-64) | 리프팅 → SSA·최적화 → 호출 인자·스택 버퍼·카나리 → out-of-SSA → 구조화 → C 출력(`relic decompile`) |

> 인자 추적 기반 탐지(포맷 스트링, ret2win)와 점프 테이블 복원은 현재 **x86-64에서만** 동작합니다.

## 설치

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Python 3.10 이상, 의존성: capstone, pyelftools, pefile, PySide6.

## 사용법

```sh
relic info      ./chall              # 헤더, 섹션, 라이브러리
relic checksec  ./chall              # 보호 기법
relic funcs     ./chall [-a]         # 함수 목록 (-a: import 스텁 포함)
relic disasm    ./chall [main]       # 함수/주소 디스어셈블 (기본: main 또는 entry)
relic disasm    ./chall 0x401000 -n 20   # 선형 스윕
relic cfg       ./chall classify | dot -Tsvg > cfg.svg
relic strings   ./chall
relic imports   ./chall
relic xrefs     ./chall menu
relic strings   ./chall -g bin/sh    # 부분 문자열 검색
relic vulns     ./chall              # 포너블 휴리스틱
relic ir        ./chall vuln         # 디컴파일러 IR (리프팅 직후, 디버깅용)
relic opt       ./chall checksum --xrefs  # SSA + 최적화 IR, 문자열·교차참조, 스택 프레임
relic decompile ./chall main         # C 유사 의사 코드 (--addrs: 줄마다 명령어 주소, -a: 모든 함수)
relic disasm    sc.bin --arch x64 --base 0x1000 -n 30   # RAW blob
```

주소 인자는 `0x401000`, `401000`, `main`, `main+0x10` 형식을 받습니다.

예시 (`tests/src/vuln.c`, `-no-pie -fno-stack-protector`):

```
$ relic vulns vuln64.out
[high  ] 0x4014d0 show_note            format-string   printf() called with a non-constant format string
[high  ] 0x40162e vuln                 dangerous-call  gets() never checks bounds: stack/heap overflow
[info  ] 0x401296 win                  win-function    win runs system("/bin/sh") - ret2win target?
```

디컴파일 예시 (`-fstack-protector-strong -pie -O1`):

```
$ relic decompile vuln64_pie.out vuln
void vuln(void)
{
    char buf_58[72];  // ret-0x58
    // stack canary at ret-0x10 (check hidden)

    puts("name?");
    gets(buf_58);
    __printf_chk(1, "hello %s (%d)\n", buf_58, checksum(buf_58));
}
```

지역 변수 이름은 진입 시 스택 포인터(반환 주소 위치) 기준 오프셋입니다. `buf_58`은 반환 주소에서 0x58 아래에 있고, 크기 72는 다음 슬롯(카나리)까지의 거리입니다 — 오버플로 페이로드 계산에 그대로 쓸 수 있습니다.

## GUI

```sh
relic ./chall                        # 또는 relic gui ./chall
relic sc.bin --arch x64 --base 0x1000
```

| 키 | 동작 |
|---|---|
| `G` | 주소 / 심볼로 이동 |
| `Esc`, `Alt+←` / `Ctrl+Enter`, `Alt+→` | 뒤로 / 앞으로 |
| `Space` | 리스팅 ↔ 그래프 전환 |
| `Tab`, `F5` | 리스팅 ↔ 의사 코드 전환 (커서 위치 동기화) |
| `Ctrl+H` | 헥스 뷰 |
| `Ctrl+F` | 함수 필터 |
| `N` | 이름 변경 (함수·라벨, 커서 줄의 호출 대상; 의사 코드에서는 커서 아래 지역 변수·매개변수) |
| `;` | 주석 |
| `X` | xref 패널 |
| `Ctrl+S` | 프로젝트 저장 (`<binary>.relic.json`) |

더블클릭으로 분기 대상·심볼(의사 코드에서는 함수·전역 이름, `loc_` 레이블)을 따라갑니다. 의사 코드는 탭을 열 때 함수 단위로 백그라운드에서 디컴파일하고(그동안 GUI는 멈추지 않음) 캐시하며, 이름 변경은 바로 반영됩니다. 문자열 테이블에서 더블클릭하면 그 문자열을 참조하는 코드로 이동합니다.

## 라이브러리로 사용

```python
from relic.analysis import analyze

an = analyze("./chall")
main = an.function_by_name("main")
for blk in main.blocks.values():
    print(hex(blk.addr), [hex(s) for s in blk.succs])
print(an.checksec())
for v in an.vulns():
    print(v.severity, hex(v.addr), v.message)
```

## 구조

```
relic/
  loader/      ELF / PE / RAW → 공통 Binary 모델 (섹션, 세그먼트, 심볼, import, 재배치)
  disasm.py    capstone 래퍼, 명령어 분류(call/jmp/cjmp/ret/halt), 분기 대상·데이터 참조 추출
  analysis/    함수 탐색·CFG(functions), 문자열, checksec, 취약점 휴리스틱, xref, 프로젝트 저장
  decompiler/  IR, 리프터(x86/x64), SSA·최적화, 호출/스택 복원, 구조화, C 출력 (docs/decompiler-plan.md)
  listing.py   심볼/문자열 주석이 붙은 디스어셈블리 리스팅 (CLI·GUI 공용)
  gui/         PySide6 메인 윈도우와 뷰 위젯
  __main__.py  CLI
tests/
  src/vuln.c   테스트용 포너블 샘플 (테스트 실행 시 tests/bins/에 빌드)
```

## 테스트

```sh
.venv/bin/pytest -q
```

gcc가 있으면 `tests/src/vuln.c`를 여러 변형(no-PIE, PIE+보호기법, strip)으로 빌드해 검증합니다. 디컴파일러는 IR 인터프리터로 각 변환 단계의 의미 보존을 확인하고, `checksum`·`classify`의 디컴파일 결과를 다시 컴파일해 원본 소스와 같은 결과를 내는지 비교합니다. 컴파일러가 없으면 해당 테스트는 skip됩니다. GUI 테스트는 `QT_QPA_PLATFORM=offscreen`으로 실행되며, Qt 시스템 라이브러리(libEGL 등)가 없으면 skip됩니다.

## 라이선스

MIT
