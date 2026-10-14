# Relic

리버싱과 포너블을 위한 디스어셈블러 / 디컴파일러 (WIP).

**목표: IDA Pro(+ Hex-Rays) 이상.** 아래 표는 IDA Pro를 기준선으로 한 현재 스펙과 진행률입니다.
진행 상황 세부는 [TODO.md](TODO.md), 디컴파일러 설계는 [docs/decompiler-plan.md](docs/decompiler-plan.md)를 참고하세요.

## 목표 대비 진행률 (기준: IDA Pro 9 + Hex-Rays)

진행률은 "IDA Pro가 그 영역에서 하는 일 중 Relic이 같은 수준으로 하는 비율"을 어림한 값입니다.
전체 값은 영역 가중 평균(가중치는 리버싱 실무에서의 비중)입니다.

**전체: 약 33%** — 분석·디컴파일 핵심 경로는 x86/ARM 계열에서 실사용 가능, 타입 시스템·라이브러리 식별·스크립팅 콘솔이 큰 격차.

| 영역 (가중치) | IDA Pro 기준 | Relic 현재 | 진행률 |
|---|---|---|---|
| 파일 포맷 (8) | ELF, PE, Mach-O, COFF/OMF, 펌웨어·raw 등 수십 종 | ELF, PE(import/export/COFF 심볼/.pdata), RAW | 35% |
| 프로세서 (8) | 60여 개 CPU 계열 | 디스어셈블 7종(x86, x64, ARM/Thumb, AArch64, MIPS, RISC-V, PPC), 분석·리프팅은 x86/x64/ARM/AArch64 | 35% |
| 자동 분석 (14) | 함수·CFG·xref·점프 테이블·noreturn·문자열·stripped 복구 | 재귀 하강 + 프롤로그 스캔, 점프 테이블(x86/ARM/AArch64), 레지스터 상수 전파로 데이터 xref, stripped `main` 복구, ARM/Thumb 상호 운용 | 55% |
| 라이브러리 식별 (8) | FLIRT 시그니처, Lumina | 없음 (심볼·import·PLT 이름만) | 0% |
| 타입 시스템 (10) | 구조체·열거형·로컬 타입, 타입 라이브러리, 타입 전파 | int/포인터/unsigned 추론, libc 시그니처 일부 | 10% |
| 디컴파일러 (20) | Hex-Rays: 다수 아키텍처, 타입·구조체 대화형 수정, 부동소수점 | x86-64/x86-32/AArch64/ARM32, 재컴파일 검증, 구조화(switch·for·&&), 상수 나눗셈, -fipa-ra 레지스터 보존; 구조체·부동소수점·대화형 재타입 없음 | 40% |
| 대화형 UI (12) | 리스팅·그래프·xref·이름/주석·검색·패치·undo·북마크·구조체 창 | 리스팅·그래프(층별 레이아웃)·의사 코드·헥스, 이름/주석/변수 이름, xref, 이동 기록, 테마·확대, 검색(바이트·텍스트·즉치값·명령어); 패치·undo·북마크 없음 | 47% |
| 스크립팅·확장 (8) | IDAPython, IDC, SDK, 플러그인 | Python 라이브러리 API (`relic.analysis`, `relic.decompiler`), CLI | 20% |
| 디버거 (7) | 로컬·원격(gdbserver 등) 디버깅 | 로컬 GUI 디버거(GDB/MI): 실행·단계 실행·중단점(조건·활성화·적중 횟수)·리스팅 동기화, pwndbg식 레지스터·스택 telescope·vmmap·메모리 hexdump·백트레이스·콘솔, PIE 슬라이드 보정; 원격·메모리 편집·힙 뷰 없음 | 30% |
| 프로젝트·협업 (5) | IDB, 스냅숏, Teams, Lumina | `<binary>.relic.json`(이름·주석·변수 이름) | 15% |

IDA Pro에 없는 Relic 쪽 기능: checksec(ELF/PE 보호 기법), 포너블 휴리스틱(위험 함수, 비상수 포맷 스트링, 폭 없는 `scanf("%s")`, ret2win 후보), 디컴파일 결과의 재컴파일 검증 하네스.

### 다음 단계 (격차가 큰 순)

1. ~~검색(텍스트·바이트 패턴·즉치값·명령어)~~ (완료), 바이트 패치·패치된 바이너리 저장
2. GUI 안의 Python 콘솔과 플러그인 진입점 (IDAPython 대응)
3. 정적 링크 라이브러리 함수 식별 (FLIRT 대응 시그니처)
4. 구조체·타입 시스템과 디컴파일러 연동 (필드 접근 `p->size`)
5. Mach-O 로더, MIPS / RISC-V 리프터
6. 디버거 보강: watchpoint·힙 정보 패널, 레지스터·메모리 값 편집

## 기능

| 영역 | 상태 |
|---|---|
| 로더 | ELF / PE(import, export, COFF 심볼) / RAW(셸코드·펌웨어 blob) |
| 디스어셈블 | capstone 기반: x86, x64, ARM, AArch64, MIPS, RISC-V, PPC |
| 함수 탐색 / CFG | 재귀 하강, noreturn 처리, tail call, x86-64 점프 테이블 복원 |
| stripped 바이너리 | `__libc_start_main` 인자로 `main` 복구, 프롤로그 스캔, `.init_array` 시드 |
| 참조 | 코드/데이터 xref, 문자열(ASCII, PE는 UTF-16LE) |
| C++ | Itanium 심볼 디맹글링 (`geo::Rect::area() const`), 짧은 이름으로 이동·디컴파일 (`relic decompile ./a.out geo::total`) |
| checksec | ELF: RELRO / Canary / NX / PIE / FORTIFY / RPATH, PE: ASLR / DEP / CFG / SEH / GS |
| 포너블 휴리스틱 | `gets`·`strcpy` 등 위험 함수, 비상수 포맷 스트링, 폭 없는 `scanf("%s")`, ret2win 후보 |
| 프로젝트 | 이름 변경·주석·디컴파일러 변수 이름을 `<binary>.relic.json`에 저장 (CLI 출력에도 반영) |
| GUI | 함수 목록, 디스어셈블리 / CFG 그래프 / 의사 코드 / 헥스, xref·문자열·import·vulns·checksec 패널 |
| 디컴파일러 (x86-64, x86-32, AArch64, ARM32) | 리프팅 → SSA·최적화 → 호출 인자·스택 버퍼·카나리 → out-of-SSA → 구조화 → C 출력(`relic decompile`) |

> 인자 추적 기반 탐지(포맷 스트링, ret2win)는 **x86-64·x86-32·AArch64·ARM32**, 점프 테이블 복원은 **x86-64·x86-32·AArch64·ARM32**에서 동작합니다.

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
relic search    ./chall --bytes '48 8b ?? 05'   # 바이트 패턴 (--text, --imm 0x186a0, --insn 'call.*system')
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
| `Alt+B` / `Alt+T` / `Alt+I` / `Ctrl+Alt+I` | 바이트 패턴(`48 8b ?? 05`) / 텍스트 / 즉치값 / 명령어 정규식 검색 (결과는 Search 패널) |
| `F9` / `Shift+F9` | 디버거 시작·계속 / `main`에서 멈추게 시작 |
| `F7` / `F8` / `Ctrl+F7` | 한 명령 단계 실행(들어감) / 건너뜀 / 함수 끝까지 |
| `F4` / `F2` | 커서까지 실행 / 중단점 토글 |
| `Ctrl+Alt+Pause` / `Ctrl+F2` | 일시 정지 / 종료 |
| `Ctrl+.` | 실행 중인 분석 / 취약점 스캔 / 검색 취소 |
| `Ctrl+Shift+L` | 라이트 / 다크 테마 전환 |
| `Ctrl+=` / `Ctrl+-` / `Ctrl+0` | 코드 글꼴 크게 / 작게 / 기본 (테마·크기는 저장됨) |

더블클릭으로 분기 대상·심볼(의사 코드에서는 함수·전역 이름, `loc_` 레이블)을 따라갑니다. 의사 코드는 탭을 열 때 함수 단위로 백그라운드에서 디컴파일하고(그동안 GUI는 멈추지 않음) 캐시하며, 이름 변경은 바로 반영됩니다. 문자열 테이블에서 더블클릭하면 그 문자열을 참조하는 코드로 이동합니다.

분석과 취약점 스캔은 백그라운드에서 돌며 상태 표시줄에 진행 상황과 Cancel 버튼이 나옵니다. 창을 닫으면 실행 중인 작업을 기다리지 않고 취소합니다. 스캔이 실패하면 Vulns 표에 빈 결과 대신 오류가 표시됩니다. CFG 그래프는 층별 배치(루프는 위로 돌아가는 간선, 긴 간선은 블록 사이로 우회, 교차 최소화)로 그립니다.

### 디버거 (로컬, pwndbg 스타일 GUI)

Debug 메뉴(`F9`)가 열린 바이너리를 로컬 `gdb`(GDB/MI)로 실행합니다. 모든 디버깅은 이 컴퓨터에서 돌며 원격 연결은 없습니다. 프로그램 인자는 Debug → Program arguments에서 지정하고, 표준 입출력은 Console 패널(pty)로 주고받습니다(아래 줄은 gdb 명령).

- **Registers**: 범용 레지스터, 바뀐 값 강조, 포인터는 pwndbg처럼 가리키는 곳(코드 심볼·문자열·스택/힙 체인)을 표시
- **Stack**: `telescope` — 스택 워드와 포인터 체인, 매핑 종류(code/stack/heap/data)별 색
- **Backtrace** / **Code**: 호출 스택(클릭하면 해당 위치로 이동), 현재 pc 주변 디스어셈블
- **Breakpoints**: 중단점 목록(체크로 활성/비활성, 조건 `$rdi == 5` 편집, 적중 횟수), 실행을 다시 시작해도 유지
- **Vmmap** / **Memory**: 프로세스 메모리 맵(종류별 색), 주소·식(`$rsp+8`, `main`, `0x7ffd...`)의 hexdump. 레지스터·스택 값이나 매핑을 더블클릭하면 분석한 바이너리의 코드는 리스팅으로, 그 밖은 Memory 뷰로 따라갑니다
- 리스팅에서 현재 pc 줄은 초록, 중단점은 빨강으로 표시하며 멈출 때마다 정적 주소로 따라갑니다(PIE 슬라이드는 자동 보정)


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
  decompiler/  IR, 리프터(x86/x64, AArch64, ARM32), SSA·최적화, 호출/스택 복원, 구조화, C 출력 (docs/decompiler-plan.md)
  listing.py   심볼/문자열 주석이 붙은 디스어셈블리 리스팅 (CLI·GUI 공용)
  gui/         PySide6 메인 윈도우와 뷰 위젯, CFG 층별 레이아웃(layout.py)
  progress.py  백그라운드 작업 취소 토큰·진행 보고
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
