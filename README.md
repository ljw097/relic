# Relic

리버싱하고 포너블 문제 풀 때 쓰려고 만들고 있는 디스어셈블러 겸 디컴파일러입니다.
GUI는 PySide6, 디스어셈블은 capstone을 쓰고, 그 위의 분석·디컴파일·디버거는 직접 짰습니다.

목표는 솔직히 크게 잡았습니다 — IDA Pro + Hex-Rays만큼, 할 수 있으면 그 이상.
아직 갈 길이 멀지만 x86-64나 ARM 바이너리 하나 열어서 함수 보고, 이름 붙이고, 의사 코드 읽고,
디버거로 오프셋 재는 정도는 이걸로 충분히 됩니다. 지금은 [0.1.0 베타](https://github.com/ljw097/relic/releases/tag/v0.1.0)입니다.

![Relic 디버거: vuln()에서 gets() 직후 멈춘 상태 — 레지스터·스택 telescope에 입력한 AAAA…가 보인다](docs/screenshots/debugger.png)

## 설치

릴리스 페이지의 wheel을 받아서 깔면 됩니다.

```sh
python3 -m venv .venv
.venv/bin/pip install https://github.com/ljw097/relic/releases/download/v0.1.0/relic_re-0.1.0-py3-none-any.whl
.venv/bin/relic ./chall
```

소스에서 돌리려면:

```sh
git clone https://github.com/ljw097/relic && cd relic
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Python 3.10 이상, 리눅스에서 씁니다. 디버거는 `gdb`가 필요하고(`sudo apt install gdb`), ARM·MIPS 같은
다른 아키텍처 바이너리를 디버깅하려면 `gdb-multiarch`와 `qemu-user`도 깔아 두세요.
`Ctrl+Alt+A`(어셈블해서 패치)는 keystone이 있어야 해서 `pip install 'relic-re[asm]'`로 따로 받습니다.

## 뭘 할 수 있나

| | |
|---|---|
| ![리스팅](docs/screenshots/listing.png) | ![그래프](docs/screenshots/graph.png) |
| 리스팅. 문자열 참조는 주석으로, 호출 대상은 이름으로 보입니다 | CFG 그래프. 분기함/안 함은 초록/빨강, 루프는 옆으로 돌아 올라갑니다 |
| ![의사 코드](docs/screenshots/pseudocode.png) | ![취약점](docs/screenshots/vulns.png) |
| 의사 코드. 점프 테이블이 `switch`로 돌아옵니다 | Vulns 탭. 포맷 스트링, `gets()`, ret2win 후보 |

(스크린샷은 전부 [`tests/src/vuln.c`](tests/src/vuln.c)를 연 화면입니다.)

대충 이런 것들이 됩니다.

- **여는 파일**: ELF(실행 파일, 공유 라이브러리, `.o`, 코어 덤프), PE, COFF 객체, `.a` 안의 멤버,
  Intel HEX / S-record, 그냥 raw 덤프. raw 펌웨어는 적재 주소도 추측해 줍니다(`--base auto`).
- **아키텍처**: 디컴파일까지 되는 건 x86, x86-64, ARM/Thumb, AArch64, MIPS32, RISC-V(RV64GC).
  PPC는 디스어셈블만 됩니다.
- **분석**: 함수·CFG·xref·문자열, 점프 테이블, stripped 바이너리에서 `main` 찾기, 어떤 컴파일러와
  libc로 빌드했는지 알아내기.
- **라이브러리 함수 이름**: 정적 링크된 stripped 바이너리에서 libc 함수를 시그니처로 찾아 이름을 붙입니다.
  설치된 툴체인에서 시그니처를 알아서 만들 수도 있습니다(`relic sigs build --system`).
- **디컴파일러**: 구조체를 알아서 복원하고, 타입을 직접 줄 수도 있습니다(`Y`). 부동소수점, libc·Windows API
  원형, C 헤더 가져오기도 됩니다. 결과를 다시 컴파일해서 원본과 같게 도는지 확인하는 테스트도 있습니다.
- **GUI**: 이름·주석·xref·검색·북마크·바이트 패치·undo처럼 IDA에서 손에 익은 것들은 대부분 있고,
  단축키도 웬만하면 IDA랑 같게 맞췄습니다.
- **디버거**: gdb를 뒤에 두고 pwndbg 느낌으로 만들었습니다. 로컬, gdbserver, qemu-user, 실행 중인 프로세스에
  붙기까지 되고, 레지스터·스택 telescope·vmmap·힙 청크도 볼 수 있습니다.
- **스크립팅**: GUI 안 Python 콘솔, `relic script`, 플러그인.
- **포너블용**: checksec, 위험 함수, 비상수 포맷 스트링, 폭 없는 `scanf("%s")`, ret2win 후보.
  이건 IDA에 없어서 따로 만든 것들입니다.

### IDA랑 비교하면 지금 어디쯤인가

어림잡아 매긴 숫자입니다. "IDA가 그 영역에서 해 주는 것 중 Relic이 비슷한 수준으로 하는 비율" 정도로 봐 주세요.
전체는 영역별 가중 평균인데, 가중치는 제가 실제로 리버싱할 때 체감하는 비중으로 정했습니다. 지금 **대략 75%**입니다.

| 영역 (가중치) | 진행률 | 메모 |
|---|---|---|
| 파일 포맷 (8) | 70% | Mach-O가 없습니다 |
| 프로세서 (8) | 46% | IDA는 60종 넘게 지원하니 여기가 제일 멀어요 |
| 자동 분석 (14) | 55% | 큰 바이너리에서 아직 놓치는 함수·점프가 있습니다 |
| 라이브러리 식별 (8) | 100% | stripped 정적 C 바이너리에서 83~94%, 오식별 0 |
| 타입 시스템 (10) | 85% | |
| 디컴파일러 (20) | 52% | goto가 많이 남고 x87·SIMD가 없습니다 |
| 대화형 UI (12) | 100% | |
| 스크립팅·확장 (8) | 100% | |
| 디버거 (7) | 90% | |
| 프로젝트·협업 (5) | 100% | 스냅숏, 버전 기록, 병합, Lumina 비슷한 이름 공유 |

영역마다 무엇을 기준으로 100%라고 했는지, 뭐가 남았는지는 [TODO.md](TODO.md)에 적어 뒀습니다.
끝난 일의 기록은 [docs/history.md](docs/history.md)에 있습니다.

## CLI

GUI 없이도 대부분 됩니다. 자주 쓰는 것만 추리면:

```sh
relic info      ./chall              # 헤더, 섹션, 라이브러리, 컴파일러
relic checksec  ./chall
relic funcs     ./chall
relic disasm    ./chall main
relic decompile ./chall main
relic vulns     ./chall
relic strings   ./chall -g bin/sh
relic xrefs     ./chall menu
```

조금 덜 자주 쓰지만 알아 두면 편한 것들:

```sh
relic decompile ./chall -a -o chall.c            # 전체를 C 파일 하나로
relic decompile ./chall main --header chall.h    # 내가 쓴 구조체 선언을 써서
relic cfg       ./chall classify | dot -Tsvg > cfg.svg
relic search    ./chall --bytes '48 8b ?? 05'    # --text, --imm 0x186a0, --insn 'call.*system'
relic patch     ./chall main+0x2f --invert       # 분기 뒤집어서 ./chall.patched로
relic script    ./chall rename_all.py
relic sigs build /usr/lib/x86_64-linux-gnu/libc.a -o ~/.relic/sigs/glibc-x64.sig
relic project   ./chall commit -m "named the parser"
relic disasm    sc.bin --arch x64 --base 0x1000 -n 30   # 셸코드 같은 raw blob
```

주소는 `0x401000`, `401000`, `main`, `main+0x10` 어느 쪽으로 써도 됩니다.
`relic <명령> -h`로 옵션을 볼 수 있습니다.

### 예시

`tests/src/vuln.c`를 `-no-pie -fno-stack-protector`로 빌드해서 돌려 보면:

```
$ relic vulns vuln64.out
[high  ] 0x4014d0 show_note            format-string   printf() called with a non-constant format string
[high  ] 0x40162e vuln                 dangerous-call  gets() never checks bounds: stack/heap overflow
[info  ] 0x401296 win                  win-function    win runs system("/bin/sh") - ret2win target?
```

같은 소스를 `-fstack-protector-strong -pie -O1`로 빌드하고 디컴파일하면:

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

지역 변수 이름의 숫자는 반환 주소에서 얼마나 떨어져 있는지입니다. `buf_58`은 반환 주소 0x58 아래에 있으니,
페이로드는 0x58바이트 채우고 바로 반환 주소를 덮으면 됩니다(카나리가 없다면요). 포너블 하다 보면 이게 제일 편합니다.

구조체도 알아서 잡아 줍니다. 전역 배열 `notes`가 가리키는 구조체는 그 배열을 쓰는 함수들끼리 같은 정의를 공유합니다.

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

GUI에서 `N`으로 `struct note { char *data; int size; }`처럼 이름을 바꾸면 다른 함수에서도 다 바뀌어 보입니다.

## GUI

```sh
relic ./chall          # = relic gui ./chall
```

처음 열면 이렇게 쓰면 됩니다.

1. 분석은 백그라운드에서 돌고, 끝나면 `main`으로 갑니다. stripped여도 `main`을 찾아 줍니다.
2. 왼쪽 함수 목록에서 더블클릭해 들어가고, `call` 대상도 더블클릭하면 따라갑니다. `Esc`로 돌아옵니다.
3. `Space`는 그래프, `Tab`은 의사 코드, `Ctrl+H`는 헥스입니다. 뷰를 바꿔도 커서 위치는 따라옵니다.
4. 읽으면서 `N`으로 이름 붙이고 `;`로 주석 달고, `Ctrl+S`로 저장합니다. 저장은 바이너리 옆 `<binary>.relic.json`에 됩니다.
5. 아래 Vulns, Checksec 탭은 포너블 할 때 먼저 한 번 훑어보면 좋습니다.

### 단축키

IDA를 써 봤으면 거의 그대로입니다.

| 키 | 동작 |
|---|---|
| `G` | 주소 / 심볼로 이동 |
| `Esc` / `Ctrl+Enter` | 뒤로 / 앞으로 |
| `Space` | 리스팅 ↔ 그래프 |
| `Tab`, `F5` | 리스팅 ↔ 의사 코드 |
| `Ctrl+H` | 헥스 |
| `N` | 이름 바꾸기 (의사 코드에서는 변수·구조체·필드도) |
| `;` | 주석 |
| `Y` | 타입 지정 (`char *`, `struct note *` …) |
| `X` | xref |
| `U` / `C` / `D` / `A` / `P` | 정의 해제 / 코드 / 데이터 / 문자열 / 함수 만들기 |
| `H` / `R` / `B` | 숫자를 16진↔10진 / 문자 / 2진으로 |
| `Alt+B` / `Alt+T` / `Alt+I` | 바이트 패턴 / 텍스트 / 즉치값 검색 |
| `Ctrl+Z` / `Ctrl+Shift+Z` | 되돌리기 / 다시 하기 |
| `Alt+M` / `Ctrl+M` | 북마크 추가 / 북마크 목록 |
| `Ctrl+Shift+S` | 구조체 창 |
| `Ctrl+Shift+P` | Python 콘솔 |
| `Shift+F5` | 시그니처 창 |
| `Ctrl+Alt+N` / `Ctrl+Alt+J` / `Ctrl+Alt+A` | NOP으로 / 분기 뒤집기 / 어셈블해서 패치 |
| `F9` / `F7` / `F8` / `F4` / `F2` | 디버거 실행·계속 / 들어가기 / 건너뛰기 / 커서까지 / 중단점 |
| `Ctrl+Shift+L` | 라이트 / 다크 테마 |
| `Ctrl+=` / `Ctrl+-` | 글꼴 크게 / 작게 |
| `Ctrl+.` | 돌고 있는 분석·검색 취소 |

### 디버거

Debug 메뉴(`F9`)로 지금 열린 바이너리를 gdb 밑에서 실행합니다. 원격 gdbserver에 붙거나, 다른 아키텍처 바이너리를
qemu-user로 돌리거나, 이미 떠 있는 프로세스에 붙는 건 Debug ▸ Debugger target에서 고릅니다. 프로그램 입출력은 Console 패널에서 주고받습니다.

패널은 pwndbg를 써 봤다면 익숙할 겁니다. Registers에서는 바뀐 값이 강조되고 포인터가 가리키는 곳이 같이 보입니다.
Stack은 telescope, 그 밖에 Backtrace, Vmmap, Memory, Breakpoints, Threads, Modules 패널이 있습니다.
값을 더블클릭하면 코드는 리스팅으로, 나머지는 Memory로 따라갑니다. 바이너리를 패치해 뒀다면 디버거는 패치된 쪽을 실행합니다.

#### 해 보기: `vuln()` 오버플로 오프셋 재기

맨 위 스크린샷이 이 순서로 찍은 겁니다. `tests/bins/vuln64.out`은 테스트를 한 번 돌리면 생깁니다.

1. `relic tests/bins/vuln64.out`으로 열고, Debug ▸ Program arguments에 `5`를 넣습니다. 인자가 있으면 `main`이 `vuln()`을 부릅니다.
2. `vuln`으로 가서 `F2`로 중단점을 겁니다.
3. `F9`를 두 번 누르면 entry에서 한 번 서고, 그다음 `vuln`에서 섭니다.
4. `call gets` 바로 다음 줄에 커서를 두고 `F4`. 입력을 기다리면 Console의 stdin 줄에 `AAAAAAAABBBBBBBB`를 넣습니다.
5. Stack 패널에서 `0x4141414141414141`이 보이고, 몇 줄 아래에 반환 주소 `main+0x3c`가 보입니다.
6. Memory 탭에 `$rbp-0x40`을 넣으면 버퍼부터 덤프가 나옵니다. 의사 코드의 `char buf_48[64]; // ret-0x48`처럼 반환 주소까지는 0x48바이트입니다.

Console의 `gdb>` 줄에는 `x/8gx $rsp` 같은 gdb 명령을 그대로 쳐도 됩니다.
도커 안이라면 ptrace 권한(`--cap-add=SYS_PTRACE`)이 있어야 gdb가 제대로 돕니다.

## 스크립팅

GUI의 Python 콘솔(`Ctrl+Shift+P`), 플러그인, `relic script` 전부 같은 함수들을 씁니다.
`here()`, `goto()`, `rename()`, `comment()`, `functions()`, `xrefs_to()`, `decompile()`, `search()`, `patch()` 같은 것들이고,
전체 목록은 [docs/scripting.md](docs/scripting.md)에 있습니다.

플러그인은 `~/.relic/plugins/`에 파이썬 파일을 넣고 `register(api)`만 만들면 됩니다.

```python
# ~/.relic/plugins/mark_gets.py
def register(api):
    def run(ns):
        for f in ns["functions"]():
            if "gets(" in ns["decompile"](f):
                ns["comment"](f.addr, "calls gets")
    api.add_action("Mark gets() callers", run, "Ctrl+Alt+G")     # Plugins 메뉴에 들어갑니다

    def deco(an, line):                                           # 리스팅 줄에 주석·색 입히기
        if line.mnemonic == "call" and "gets" in line.operands:
            return {"comment": "unbounded read", "color": "#5a1e1e"}
    api.add_line_decorator(deco)
```

플러그인에서 예외가 나도 GUI는 멀쩡하고, 에러는 Python 콘솔에 찍힙니다.

라이브러리처럼 가져다 써도 됩니다.

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
  loader/      ELF / PE / COFF / 코어 덤프 / 펌웨어 → 공통 Binary 모델
  disasm.py    capstone 래퍼
  analysis/    함수·CFG, xref, 문자열, 시그니처, 컴파일러 식별, checksec, 취약점, 프로젝트 저장
  decompiler/  리프터 → SSA·최적화 → 구조화 → C 출력 (설계는 docs/decompiler-plan.md)
  debugger/    gdb/MI 세션
  gui/         PySide6 창과 뷰
  scripting.py 콘솔·플러그인·relic script가 같이 쓰는 API
  __main__.py  CLI
```

## 테스트

```sh
.venv/bin/pytest -q
.venv/bin/ruff check .
```

테스트는 gcc나 크로스 컴파일러로 샘플을 그 자리에서 빌드해서 돌립니다. 디컴파일 결과를 다시 컴파일해서
원본과 같은 값을 내는지까지 봅니다. 컴파일러가 없으면 그 테스트는 skip되고, GUI 테스트는 `QT_QPA_PLATFORM=offscreen`으로 돕니다.

버그나 이상한 디컴파일 결과를 보면 이슈로 바이너리와 같이 남겨 주시면 고맙겠습니다.

## 라이선스

MIT
