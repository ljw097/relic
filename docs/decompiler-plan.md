# 디컴파일러 계획

상태: 단계 2 완료 (SSA + 최적화 패스 + 인터프리터 SSA 실행, `relic/decompiler/`). 이 문서는 구현 순서와 모듈 경계를 정한다.

## 목표

- 기존 분석 결과(`Analysis`, `Function`, `Block`, `Insn`)를 입력으로 받아 함수 단위로 **읽기 쉬운 C 유사 의사 코드**를 만든다.
- 포너블에 필요한 정보를 우선한다: 지역 버퍼 크기와 스택 오프셋, 호출 인자(특히 문자열 상수), 루프·분기 조건.
- 정확성 > 가독성. 복원할 수 없는 부분은 숨기지 않고 그대로 드러낸다(`/* unresolved */`, `goto`).

## 비목표 (당분간)

- 재컴파일 가능한 C 출력
- C++ 클래스·가상 함수 복원, 예외 처리 흐름
- 부동소수점·SIMD의 정확한 의미 (초기에는 내장 함수 호출로 표현)
- 전체 프로그램 단위 타입 추론 (함수 단위로 시작)

## 파이프라인

```
Function (blocks, insns)
  │ 1. lift           아키텍처별 리프터 → IR 문장 리스트 (블록 단위)
  ▼
IR CFG
  │ 2. ssa            지배자 트리, phi 삽입, 변수 버전 부여
  │ 3. optimize       상수/복사 전파, 플래그 → 비교식 결합, 죽은 코드 제거
  │ 4. calls/stack    호출 인자·반환값 복원, 스택 슬롯 → 지역 변수
  │ 5. out-of-ssa     phi 제거, 변수 병합
  ▼
IR CFG (변수 단위)
  │ 6. structure      if/else, while/do-while/for, switch, break/continue, goto
  ▼
AST
  │ 7. types          포인터/정수/크기 추론, 문자열 인자 표시
  │ 8. emit           C 텍스트 + 주소 매핑
  ▼
의사 코드
```

## 모듈 구성 (예정)

```
relic/decompiler/
  __init__.py     decompile(analysis, func) -> Decompiled (text + addr↔line 매핑)
  ir.py           IR 정의
  lift/
    __init__.py   리프터 선택
    x86.py        x86 / x64
  ssa.py          지배자, phi 삽입, 이름 부여
  passes.py       상수/복사 전파, load 전달, 조건식 복원, DCE (구현됨)
  refs.py         IR 문자열/교차참조 추출, 주석 포함 출력 (구현됨)
  calls.py        호출 규약, 인자/반환값
  stack.py        스택 프레임 → 지역 변수
  structure.py    제어 흐름 구조화
  types.py        타입 추론
  emit.py         C 출력
  interp.py       IR 인터프리터 (리프팅·최적화 패스의 의미 보존 테스트용)
```

`relic.analysis`는 디컴파일러를 몰라도 동작해야 한다. 의존 방향은 `decompiler → analysis → disasm → loader`.

## 1. IR

작은 3-주소 형식의 IR을 쓴다. 모든 값에 비트 폭이 있다.

- **값(Expr)**: `Const(v, bits)`, `Reg(name, bits)`, `Var(name, version, bits)`, `Load(addr, bits)`, `BinOp(op, a, b)`, `UnOp(op, a)`, `Cast(kind, a, bits)`, `Call(target, args)`, `Phi(sources)`
- **문장(Stmt)**: `Assign(dst, expr)`, `Store(addr, expr, bits)`, `Branch(cond, true, false)`, `Jump(target)`, `IndirectJump(expr, targets)`, `CallStmt(call)`, `Return(expr?)`, `Unknown(insn)`
- 각 문장에 원래 명령어 주소를 붙여 GUI에서 디스어셈블리와 연결한다.
- 플래그는 처음에 개별 레지스터(`ZF`, `CF`, `SF`, `OF`)로 리프팅하고, 최적화 단계에서 `cmp`/`test`와 조건 분기를 하나의 비교식으로 합친다.
- 구현 메모(단계 1): 위 목록 외에 `Extract`(상위 바이트 레지스터 등), `Ite`(cmov), `Intrinsic`(parity, SIMD 등 정밀하게 모델링하지 않는 연산), `Effect`(hlt, syscall 등) 를 추가했다. `PF`도 1비트 레지스터로 둔다. 명령어가 정의하지 않는(undefined) 플래그는 대입하지 않는다.
- 오버플로 플래그는 `carry`/`scarry`/`sborrow` 연산자로 표현해서 `cmp a, b; jl` 의 `SF != OF` 를 나중에 `a <s b` 로 접을 수 있게 한다.

## 2. 리프팅

- 첫 대상은 **x86-64**, 그다음 x86-32. capstone 상세 정보(operand, 레지스터 접근)를 사용한다.
- 부분 레지스터 쓰기 규칙: 32비트 쓰기는 상위 32비트를 0으로, 8/16비트 쓰기는 병합.
- 1차 목표 명령어군: `mov/movzx/movsx/lea`, 산술·논리, `cmp/test`, `jcc/jmp/call/ret`, `push/pop/leave`, `cmov/setcc`, `imul/idiv`, `shl/sar/shr`, `cdqe/cqo`.
- 지원하지 않는 명령어는 `Unknown(insn)`으로 남기고, 출력에 `__asm("...")`로 표시한다.
- 점프 테이블은 분석 결과(`Function.jump_tables`)를 `IndirectJump`의 후보 목록으로 사용한다.

## 3. SSA와 최적화

- 지배자 트리: Cooper–Harvey–Kennedy 반복 알고리즘(블록 수가 작아 충분).
- phi 삽입: 지배 경계 기반, 이름 부여는 지배자 트리 순회.
- 패스(고정점까지 반복): 상수 전파, 복사 전파, 식 단순화(`x ^ x → 0`, `x + 0 → x`), 플래그 결합, 죽은 코드 제거.
- 메모리는 처음에는 단일 메모리 상태로 보고, 스택 슬롯만 분리한다(4단계).
- 구현 메모(단계 2, `passes.py`):
  - 전파는 SSA 지배 성질을 이용한다. 순수(load·call 없음) 정의는 어디에나 치환하고, load를 포함한 단일 사용 정의는 같은 블록 안에서 메모리 장벽(Store/Call/Effect/Unknown)을 넘지 않을 때만 사용처로 끌어온다(`_forward_loads`).
  - 플래그 복원: `cmp a, b`가 남긴 `SF = (a-b) <s 0`, `OF = sborrow(a, b)`, `ZF = (a-b) == 0`, `CF = a <u b` 패턴을 인식해 조건식(`jcc`/`setcc`)을 `a <s b`, `a <=u b` 등으로 접는다. `!`는 비교식 안으로 밀어 넣어 `!(a < b) → b <= a`로 읽기 쉽게 만든다.
  - 상수 폴딩과 인터프리터는 `apply_binop`/`apply_unop`/`apply_cast`를 공유해 의미가 어긋나지 않게 한다.
  - DCE는 순수한 죽은 대입만 제거하고(Store/Call/Effect/Unknown은 유지), 부작용 있는 문장은 죽은 def 항목만 떼어낸다.
- 검증: 인터프리터가 SSA(phi, 호출 use/def, version-0 → 진입 레지스터)를 실행한다. 패스 전후의 함수를 같은 입력으로 돌려 결과·메모리를 비교한다(`tests/test_passes.py`).
- 문자열·교차참조: 최적화된 IR에서도 상수가 가리키는 문자열·심볼을 그대로 보이게 한다(`refs.py`의 `ir_xrefs`, `format_ir`; CLI `relic opt`).

## 4. 호출과 스택

- 호출 규약: SysV x64(rdi, rsi, rdx, rcx, r8, r9 / rax), Win64(rcx, rdx, r8, r9), cdecl(스택).
- import 함수는 이름 기반 시그니처 표(libc 주요 함수: 인자 수, 반환 타입, 포맷 함수 여부)로 인자 수를 정한다. 내부 함수는 호출 지점에서 실제로 쓰인 인자 레지스터로 추정한다.
- 스택: `rbp`/`rsp` 기준 오프셋을 정규화해서 슬롯을 만들고, 접근 크기·`lea`로 주소를 넘기는 패턴을 보고 배열(버퍼) 여부와 크기를 추정한다.
  - 예: `lea rax, [rbp-0x50]` 이 `gets`에 전달되면 `char buf[0x50]`(카나리·정렬 고려), 오프셋을 주석으로 남긴다 — 포너블에서 가장 중요한 정보.
- 카나리 load/check(`fs:0x28`, `__stack_chk_fail`)는 출력에서 숨기고 함수 주석으로 표시한다.

## 5. 제어 흐름 구조화

- 1차: 구간(interval)/지배자 기반 패턴 매칭.
  - 자연 루프 탐지(back edge) → `while`/`do-while`, 유도 변수가 보이면 `for`
  - 조건 분기의 합류점(후지배자) → `if`/`if-else`, 단락 평가(`&&`, `||`) 결합
  - `IndirectJump` + 점프 테이블 → `switch`, 같은 대상 case 묶기
  - `break`/`continue` 인식, 남는 간선은 레이블 + `goto`
- 2차(필요하면): 구조화되지 않는 경우를 줄이기 위해 노드 복제나 패턴 독립 구조화(DREAM 계열 조건 기반 방식) 검토.

## 6. 타입 추론과 출력

- 기본 타입: 폭 기반 `int8..int64`, `uint*`, 포인터, `char*`.
- 사용처로 제약을 모은다: 역참조 → 포인터, 문자열 상수 대입 → `char*`, libc 시그니처 인자 → 해당 타입, 비교 조건의 부호(`jl` vs `jb`) → signed/unsigned.
- 출력: 변수 이름 규칙(`arg1`, `var_50`, `buf_50`, 반환값 `result`), 문자열·심볼 인라인, 사용자 이름 변경(`Analysis.renames`) 반영.
- 출력 객체는 줄 ↔ 주소 매핑을 갖고 있어서 GUI·CLI에서 서로 이동할 수 있게 한다.

## 단계별 일정

| 단계 | 내용 | 완료 조건 |
|---|---|---|
| 1 | IR + x86-64 리프터 | `vuln64.out`의 모든 함수가 `Unknown` 없이 리프팅됨 ✅ |
| 2 | SSA + 최적화 패스 | `checksum` 루프의 계산식이 `h = h * 31 + s[i]`((h<<5)-h + sext(s[i])) 형태로 접힘 ✅ |
| 3 | 호출·스택 | `vuln`에서 `gets(buf)`와 `char buf[...]` 크기, `printf("hello %s (%d)\n", buf, checksum(buf))` 복원 |
| 4 | 구조화 | `main`의 `for (;;)` 메뉴 루프, `classify`의 `switch`가 goto 없이 출력 |
| 5 | 타입·출력 정리 | `-O0`/`-O1`/PIE 변형 모두에서 위 결과 유지 |
| 6 | CLI(`relic decompile`) / GUI 탭, x86-32 리프터 | CLI 테스트와 GUI 스모크 테스트 통과 |

각 단계는 `tests/src/vuln.c` 기반의 골든 테스트를 추가한다. 출력 문자열 전체 비교 대신 핵심 구문(호출, 조건, 루프 형태)의 포함 여부로 검증해 출력 형식 변경에 덜 민감하게 한다.

## 위험 요소

- **최적화된 코드**(`-O2`): 꼬리 호출, 레지스터 재사용, 조건부 이동으로 구조화가 어려워진다 → 단계 1–4는 `-O0`/`-O1` 기준으로 맞추고 `-O2`는 회귀 테스트로만 추적.
- **간접 호출·점프**: 복원 실패 시 `goto`/`(*ptr)(...)`로 남기고 분석이 멈추지 않게 한다.
- **성능**: 순수 Python이라 대형 함수에서 느릴 수 있다 → 함수 단위 지연 디컴파일과 결과 캐시, 블록·명령어 수 상한.
- **아키텍처 확장**: 리프터 외 단계가 x86에 의존하지 않도록, 호출 규약과 레지스터 정보는 `calls.py`의 아키텍처 표로만 접근한다.
