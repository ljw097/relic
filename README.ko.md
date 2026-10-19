# Relic

[English](README.md) | **한국어**

리버싱과 포너블(pwn) 문제 풀이에 쓰려고 만들고 있는 디스어셈블러·디컴파일러입니다.
GUI는 PySide6, 명령어 디코딩은 capstone을 쓰고, 그 위의 분석·디컴파일러·디버거는 모두 직접 구현했습니다.

목표는 IDA Pro + Hex-Rays 수준이고, 가능하면 그 이상입니다. 아직 갈 길이 멀지만 x86-64나 ARM 바이너리를 열어
함수를 훑어보고, 이름을 붙이고, 의사 코드를 읽고, 디버거로 오버플로 오프셋을 재는 데는 지금도 충분히 쓸 만합니다.
현재 버전은 [1.0.1](https://github.com/ljw097/relic/releases/tag/v1.0.1)입니다.

![Relic 디버거: vuln()에서 gets() 직후에 멈춘 화면. 입력한 AAAA…가 레지스터와 스택 telescope에 보인다](docs/screenshots/debugger.png)

## 설치

[릴리스 페이지](https://github.com/ljw097/relic/releases/tag/v1.0.1)에서 자기 운영체제에 맞는 실행 파일을 받아
실행하면 됩니다. 따로 설치할 것은 없습니다.

- **Windows**: `relic-<버전>-windows-x86_64.exe`
- **Linux**: `relic-<버전>-linux-x86_64.tar.gz` (파일 하나, `relic`)
- **macOS**: `relic-<버전>-macos-arm64.zip`(Apple 실리콘) 또는 `-macos-x86_64.zip`(Intel), 안에 `Relic.app`.
  서명되지 않았으므로 처음에는 오른쪽 클릭 후 열기를 선택합니다.

파일 없이 열리고, File > Open(`Ctrl+O`), File > Open Recent, 또는 창에 파일을 끌어다 놓아서 엽니다.
같은 실행 파일로 아래 명령도 쓸 수 있습니다(`relic info FILE`, `Relic.exe decompile FILE` 등).

Python 3.10 이상이 있다면 릴리스 페이지의 wheel로 패키지로 설치할 수도 있습니다.

```sh
python3 -m venv .venv
.venv/bin/pip install https://github.com/ljw097/relic/releases/download/v1.0.1/relic_re-1.0.1-py3-none-any.whl
.venv/bin/relic
```

소스에서 실행하려면:

```sh
git clone https://github.com/ljw097/relic && cd relic
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

분석과 디컴파일은 어느 운영체제에서나 같습니다. 그 밖에 기능별로 필요한 것:

- 디버거: `gdb` (`sudo apt install gdb`)
- ARM·MIPS 등 다른 아키텍처 바이너리 디버깅: `gdb-multiarch`, `qemu-user`
- 어셈블리로 패치하기(`Ctrl+Alt+A`): keystone. `pip install 'relic-re[asm]'`로 따로 설치합니다.

## 기능

| | |
|---|---|
| ![리스팅](docs/screenshots/listing.png) | ![그래프](docs/screenshots/graph.png) |
| 리스팅. 문자열 참조는 주석으로, 호출 대상은 이름으로 표시됩니다 | CFG 그래프. 분기가 성립하는 간선은 초록, 아닌 간선은 빨강이고 루프의 역방향 간선은 옆으로 돌아갑니다 |
| ![의사 코드](docs/screenshots/pseudocode.png) | ![취약점](docs/screenshots/vulns.png) |
| 의사 코드. 점프 테이블이 `switch` 문으로 복원됩니다 | Vulns 탭. 포맷 스트링 버그, `gets()` 호출, ret2win 후보를 보여 줍니다 |

(스크린샷은 모두 [`tests/src/vuln.c`](tests/src/vuln.c)를 빌드한 바이너리입니다.)

지원하는 것을 정리하면 다음과 같습니다.

- **파일 형식**: ELF(실행 파일, 공유 라이브러리, 재배치 객체 `.o`, 코어 덤프), PE, Mach-O(실행 파일, dylib,
  유니버설 파일), COFF 객체, `.a` 아카이브의 멤버,
  Intel HEX / Motorola S-record, raw 바이너리. raw 펌웨어는 로드 주소를 추정할 수 있습니다(`--base auto`).
- **아키텍처**: x86, x86-64, ARM/Thumb, AArch64, MIPS32(빅·리틀 엔디언), MIPS64, RISC-V(RV64GC),
  PowerPC(32비트, 64비트 리틀 엔디언)는 디컴파일까지 지원합니다.
- **분석**: 함수·CFG 복원, 상호 참조(xref), 문자열, 점프 테이블, stripped 바이너리에서 `main` 찾기,
  빌드에 쓰인 컴파일러와 libc 식별.
- **라이브러리 함수 식별**: 정적 링크된 stripped 바이너리에서 libc 등 라이브러리 함수를 바이트 시그니처(FLIRT 방식)로
  찾아 이름을 붙입니다. 시그니처 파일은 설치된 툴체인의 정적 라이브러리로 직접 만들 수 있습니다(`relic sigs build --system`).
- **디컴파일러**: 메모리 접근 패턴으로 구조체를 복원하고, 사용자가 타입을 지정할 수도 있습니다(`Y`).
  부동소수점 연산, libc·Windows API 함수 원형, C 헤더 가져오기를 지원합니다.
  테스트에서는 디컴파일 결과를 다시 컴파일해 원본과 같은 결과를 내는지 확인합니다.
- **GUI**: 이름 변경, 주석, xref, 검색, 북마크, 바이트 패치, 되돌리기 등 IDA에서 자주 쓰는 기능을 갖췄고,
  단축키도 가능한 한 IDA와 같게 맞췄습니다.
- **디버거**: gdb(GDB/MI)를 백엔드로 쓰고, 화면은 pwndbg와 비슷하게 구성했습니다. 로컬 실행, gdbserver 원격 연결,
  qemu-user, 실행 중인 프로세스에 붙기를 지원하며 레지스터, 스택 telescope, vmmap, glibc 힙 청크를 볼 수 있습니다.
- **스크립팅**: GUI 안의 Python 콘솔, `relic script` 일괄 실행, 플러그인.
- **포너블용 기능**: checksec, 위험 함수 호출, 상수가 아닌 포맷 문자열, 폭 지정 없는 `scanf("%s")`, ret2win 후보 탐지.
  IDA에 기본으로 없는 기능이라 따로 넣었습니다.

### IDA 대비 진행률

정밀하게 잰 값이 아니라 어림값입니다. 각 영역에서 "IDA가 하는 일 중 Relic이 비슷한 수준으로 하는 비율"로 읽어 주세요.
전체 값은 영역별 가중 평균이며, 가중치는 실제 리버싱에서 각 영역이 차지하는 비중을 제 기준으로 정했습니다.
현재 **약 91%**입니다.

| 영역 (가중치) | 진행률 | 비고 |
|---|---|---|
| 파일 형식 (8) | 100% | Mach-O와 Objective-C 메타데이터(의사 코드에 `[obj msg:arg]`) |
| 프로세서 (8) | 100% | 디컴파일: x86/x64, ARM/Thumb, AArch64, MIPS32/64, RISC-V RV32/RV64, PowerPC 32/64(ELFv1·ELFv2). 디스어셈블: SPARC, SystemZ, M68K, SH, TriCore, eBPF, WebAssembly |
| 자동 분석 (14) | 100% | stripped bash에서 `.eh_frame`에 있는 함수의 99.9%, `.eh_frame`을 지워도 99.96%를 찾음(돌아오지 않는 함수 추론, 꼬리 호출, 데이터 속 함수 포인터). RTTI로 C++ 클래스·vtable 복원(gcc/clang, MSVC), 객체를 따라가 가상 호출 대상 해석, 모든 프로세서에서 함수 포인터 변수를 거친 호출, 코드 사이 데이터 감지, bash 약 7초 |
| 라이브러리 식별 (8) | 100% | 테스트용 stripped 정적 C 바이너리에서 원래 심볼이 있던 함수의 83~94%에 이름을 붙이며, 잘못 붙인 이름은 없습니다 |
| 타입 시스템 (10) | 90% | libc 플래그 인자를 헤더 상수 이름으로(`PROT_READ \| PROT_WRITE`), 헤더의 `#define` 묶음은 열거형으로, PE는 Microsoft 비트필드 레이아웃. 구조체 값 전달(by-value) 인자·반환 미지원 |
| 디컴파일러 (20) | 60% | goto는 벤치마크 시작 때의 절반, 남은 것은 대부분 큰 상태 기계 함수(gnulib `quotearg`, gzip deflate). SSE/AVX는 Intel intrinsic으로. x87 부동소수점 미지원 |
| 대화형 UI (12) | 100% | |
| 스크립팅·확장 (8) | 100% | |
| 디버거 (7) | 100% | Windows(PE) 프로그램은 wine에서 Windows용 gdbserver.exe로 |
| 프로젝트·협업 (5) | 100% | 스냅숏, 버전 기록, 병합, Lumina 방식의 이름 공유 |

영역별로 무엇을 100%의 기준으로 삼았는지와 남은 작업은 [TODO.md](TODO.md)에,
완료한 작업의 기록은 [docs/history.md](docs/history.md)에 있습니다.

## CLI

대부분의 기능은 GUI 없이도 쓸 수 있습니다. 자주 쓰는 명령:

```sh
relic info      ./chall              # 헤더, 섹션, 링크된 라이브러리, 컴파일러
relic checksec  ./chall              # 보호 기법(NX, PIE, 카나리, RELRO 등)
relic funcs     ./chall              # 함수 목록
relic disasm    ./chall main
relic decompile ./chall main
relic vulns     ./chall              # 취약점 후보
relic strings   ./chall -g bin/sh    # 부분 문자열로 거르기(대소문자 무시)
relic xrefs     ./chall menu         # 이 주소를 참조하는 곳
relic classes   ./app                # RTTI로 복원한 C++ 클래스: 기반 클래스, vtable, 가상 메서드
```

자주는 아니지만 알아 두면 편한 명령:

```sh
relic decompile ./chall -a -o chall.c            # 바이너리 전체를 C 파일 하나로
relic decompile ./chall main --header chall.h    # 직접 작성한 구조체 선언을 적용해서
relic cfg       ./chall classify | dot -Tsvg > cfg.svg
relic search    ./chall --bytes '48 8b ?? 05'    # --text, --imm 0x186a0, --insn 'call.*system'도 가능
relic patch     ./chall main+0x2f --invert       # 조건 분기를 뒤집어 ./chall.patched로 저장
relic script    ./chall rename_all.py
relic sigs build /usr/lib/x86_64-linux-gnu/libc.a -o ~/.relic/sigs/glibc-x64.sig
relic project   ./chall commit -m "named the parser"
relic disasm    sc.bin --arch x64 --base 0x1000 -n 30   # 셸코드 같은 raw 데이터
```

주소는 `0x401000`, `401000`, `main`, `main+0x10` 중 어떤 형식으로 써도 됩니다.
명령별 옵션은 `relic <명령> -h`로 확인할 수 있습니다.

### 예시

`tests/src/vuln.c`를 `-no-pie -fno-stack-protector`로 빌드한 뒤 실행하면:

```
$ relic vulns vuln64.out
[high  ] 0x4014d0 show_note            format-string   printf() called with a non-constant format string
[high  ] 0x40162e vuln                 dangerous-call  gets() never checks bounds: stack/heap overflow
[info  ] 0x401296 win                  win-function    win runs system("/bin/sh") - ret2win target?
```

같은 소스를 `-fstack-protector-strong -pie -O1`로 빌드해 디컴파일하면:

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

지역 변수 이름의 숫자는 그 변수가 반환 주소 슬롯에서 몇 바이트 아래에 있는지를 나타냅니다.
`buf_58`은 반환 주소보다 0x58바이트 아래에서 시작하므로, 버퍼 시작부터 0x58바이트를 채우면 그다음 8바이트가 반환 주소입니다.
다만 이 빌드에는 `ret-0x10` 위치에 스택 카나리가 있어(버퍼 72 = 0x58 − 0x10바이트 바로 위), 그대로 덮어쓰면
함수가 반환하기 전에 카나리 검사에 걸립니다. 카나리를 유출해 같은 값으로 채우거나, 카나리가 없는 빌드여야 합니다.
포너블에서는 이 오프셋 표기가 가장 유용합니다.

구조체도 자동으로 복원합니다. 아래는 전역 배열 `notes`의 원소가 가리키는 구조체로,
이 배열을 쓰는 모든 함수가 같은 구조체 정의를 공유합니다.

```
$ relic decompile vuln64.out add_note
struct s_notes {  // recovered, 12 bytes
    char *f_0;
    int f_8;
};
...
        notes[var_1c] = malloc(16);
        notes[var_1c]->f_0 = malloc(var_20);
        notes[var_1c]->f_8 = var_20;
```

GUI에서 `N`으로 이 구조체를 `struct note { char *data; int size; }`처럼 고치면 다른 함수의 의사 코드에도 바로 반영됩니다.

## GUI

```sh
relic ./chall          # relic gui ./chall과 같음
```

처음 쓸 때의 흐름은 이렇습니다.

1. 바이너리를 열면 백그라운드에서 분석이 돌고, 끝나면 `main`으로 이동합니다. stripped 바이너리에서도 `main`을 찾습니다.
2. 왼쪽 함수 목록에서 더블클릭하면 그 함수로 가고, `call`의 대상을 더블클릭하면 호출된 함수로 따라갑니다. `Esc`로 돌아옵니다.
3. `Space`는 그래프, `Tab`은 의사 코드, `Ctrl+H`는 헥스 뷰입니다. 뷰를 바꿔도 커서 위치는 유지됩니다.
4. 읽으면서 `N`으로 이름을, `;`로 주석을 달고 `Ctrl+S`로 저장합니다. 바이너리 옆의 `<binary>.relic.json`에 저장되며,
   분석 결과 자체가 아니라 사용자가 한 편집(이름, 주석, 타입, 패치 등)만 저장합니다. 분석은 열 때마다 다시 합니다.
5. 포너블 문제라면 하단의 Vulns와 Checksec 탭을 먼저 확인해 보세요.

### 단축키

IDA를 써 봤다면 대부분 같은 키입니다.

| 키 | 동작 |
|---|---|
| `G` | 주소 / 심볼로 이동 |
| `Esc` / `Ctrl+Enter` | 뒤로 / 앞으로 |
| `Space` | 리스팅 ↔ 그래프 |
| `Tab`, `F5` | 리스팅 ↔ 의사 코드 |
| `Ctrl+H` | 헥스 뷰 |
| `N` | 이름 바꾸기 (의사 코드에서는 변수, 구조체, 필드도) |
| `;` | 주석 |
| `Y` | 타입 지정 (`char *`, `struct note *` 등) |
| `X` | 상호 참조(xref) |
| `U` / `C` / `D` / `A` / `P` | 정의 해제 / 코드로 / 데이터로 / 문자열로 / 함수 만들기 |
| `H` / `R` / `B` | 숫자 표시를 16진↔10진 / 문자 / 2진으로 |
| `Alt+B` / `Alt+T` / `Alt+I` | 바이트 패턴 / 텍스트 / 즉칫값 검색 |
| `Ctrl+Z` / `Ctrl+Shift+Z` | 실행 취소 / 다시 실행 |
| `Alt+M` / `Ctrl+M` | 북마크 추가 / 북마크 목록 |
| `Ctrl+Shift+S` | 구조체 창 |
| `Ctrl+Shift+P` | Python 콘솔 |
| `Shift+F5` | 시그니처 창 |
| `Ctrl+Alt+N` / `Ctrl+Alt+J` / `Ctrl+Alt+A` | NOP으로 채우기 / 조건 분기 뒤집기 / 어셈블리로 패치 |
| `F9` / `F7` / `F8` / `F4` / `F2` | 디버거 실행·계속 / 한 단계(함수 안으로) / 한 단계(함수 건너뛰기) / 커서까지 실행 / 중단점 |
| `Ctrl+Shift+L` | 라이트 / 다크 테마 |
| `Ctrl+=` / `Ctrl+-` | 글꼴 크게 / 작게 |
| `Ctrl+.` | 진행 중인 분석·검색 취소 |

### 디버거

Debug 메뉴(`F9`)를 쓰면 열려 있는 바이너리를 gdb에서 실행합니다. 원격 gdbserver 연결, qemu-user로 다른 아키텍처
바이너리 실행, 실행 중인 프로세스에 붙기는 Debug ▸ Debugger target에서 선택합니다.
디버깅 중인 프로그램의 표준 입출력은 Console 패널로 주고받습니다.
Windows 실행 파일은 Linux에서 wine으로 띄우고 Windows용 `gdbserver.exe`로 디버깅합니다(`sudo apt install wine gdb-mingw-w64-target`).

패널 구성은 pwndbg와 비슷합니다. Registers 패널은 직전 정지 이후 바뀐 값을 강조하고, 포인터는 가리키는 값을 따라가
함께 보여 줍니다. Stack 패널은 telescope 형식이며, 그 밖에 Backtrace, Vmmap, Memory, Breakpoints, Threads, Modules
패널이 있습니다. 값을 더블클릭하면 코드 주소는 리스팅에서, 그 밖의 주소는 Memory 패널에서 엽니다.
바이너리를 패치했다면 디버거는 패치를 적용한 임시 사본을 실행합니다.

#### 따라 해 보기: `vuln()`의 오버플로 오프셋 재기

맨 위 스크린샷을 이 순서대로 찍었습니다. `tests/bins/vuln64.out`은 테스트를 한 번 실행하면 만들어집니다
(`-no-pie -fno-stack-protector` 빌드라 카나리가 없습니다).

1. `relic tests/bins/vuln64.out`으로 열고, Debug ▸ Program arguments에 `5`를 넣습니다. 인자가 있으면 `main`이 `vuln()`을 호출합니다.
2. `vuln`으로 이동해 `F2`로 중단점을 겁니다.
3. `F9`를 두 번 누릅니다. 처음에는 엔트리 포인트에서, 두 번째에는 `vuln`에서 멈춥니다.
4. `call gets` 바로 다음 줄에 커서를 두고 `F4`를 누릅니다. 프로그램이 입력을 기다리면 Console의 stdin 입력란에 `AAAAAAAABBBBBBBB`를 입력합니다.
5. Stack 패널에 `0x4141414141414141`이 보이고, 그 몇 줄 아래에 반환 주소 `main+0x3c`가 보입니다.
6. Memory 패널에 `$rbp-0x40`을 입력하면 버퍼 시작부터 덤프됩니다. 버퍼는 `rbp-0x40`에서 시작하고 저장된 `rbp`(8바이트)
   바로 위가 반환 주소이므로 오프셋은 0x40 + 8 = 0x48입니다. 의사 코드의 `char buf_48[64]; // ret-0x48`과 같은 값입니다.

Console의 `gdb>` 입력란에는 `x/8gx $rsp` 같은 gdb 명령을 그대로 입력할 수 있습니다.
Docker 컨테이너 안에서는 ptrace 권한(`--cap-add=SYS_PTRACE`)이 있어야 gdb가 정상적으로 동작합니다.

## 스크립팅

GUI의 Python 콘솔(`Ctrl+Shift+P`), 플러그인, `relic script`는 모두 같은 API를 씁니다.
`here()`, `goto()`, `rename()`, `comment()`, `functions()`, `xrefs_to()`, `decompile()`, `search()`, `patch()` 등이 있으며,
전체 목록은 [docs/scripting.md](docs/scripting.md)에 있습니다.

플러그인은 `~/.relic/plugins/`(또는 환경 변수 `RELIC_PLUGINS`에 지정한 디렉터리)에 `register(api)` 함수를 정의한
Python 파일을 두면 됩니다.

```python
# ~/.relic/plugins/mark_gets.py
def register(api):
    def run(ns):
        for f in ns["functions"]():
            if "gets(" in ns["decompile"](f):
                ns["comment"](f.addr, "calls gets")
    api.add_action("Mark gets() callers", run, "Ctrl+Alt+G")     # Plugins 메뉴에 항목 추가

    def deco(an, line):                                           # 리스팅의 각 줄에 주석·배경색 지정
        if line.mnemonic == "call" and "gets" in line.operands:
            return {"comment": "unbounded read", "color": "#5a1e1e"}
    api.add_line_decorator(deco)
```

플러그인에서 예외가 발생해도 GUI는 계속 동작하며, 오류 내용은 Python 콘솔에 출력됩니다.

Python 라이브러리로도 쓸 수 있습니다.

```python
from relic.analysis import analyze

an = analyze("./chall")
print(an.checksec())
for v in an.vulns():
    print(v.severity, hex(v.addr), v.message)
```

## 코드 구조

```
relic/
  loader/      ELF / PE / COFF / 코어 덤프 / 펌웨어를 공통 Binary 모델로 적재
  disasm.py    capstone 래퍼
  analysis/    함수·CFG, xref, 문자열, 시그니처, 컴파일러 식별, checksec, 취약점 탐지, 프로젝트 파일
  decompiler/  리프터 → SSA·최적화 → 제어 흐름 구조화 → C 출력 (설계: docs/decompiler-plan.md)
  debugger/    GDB/MI 세션
  gui/         PySide6 창과 뷰
  scripting.py 콘솔·플러그인·relic script가 공유하는 API
  __main__.py  CLI
```

## 테스트

```sh
.venv/bin/pytest -q
.venv/bin/ruff check .
```

테스트는 gcc와 크로스 컴파일러로 샘플 바이너리를 그때그때 빌드합니다. 디컴파일 결과를 다시 컴파일해
원본과 같은 값을 내는지까지 확인합니다. 필요한 컴파일러가 없는 테스트는 건너뛰고(skip),
GUI 테스트는 `QT_QPA_PLATFORM=offscreen`으로 화면 없이 실행합니다.

버그나 이상한 의사 코드를 발견하면 해당 바이너리를 첨부해 이슈로 남겨 주세요.

## 라이선스

MIT
