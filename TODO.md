# TODO

남은 작업만 적습니다. 끝난 일의 기록은 [docs/history.md](docs/history.md)에 있습니다.

우선순위: **P0** 지금 하는 일 / **P1** 다음 / **P2** 여유 있을 때.
모든 항목은 테스트(가능하면 재컴파일·실행 비교)와 함께 끝냅니다.

## P0 — 디컴파일러 속도

실제 바이너리에서 의사 코드가 느리면 GUI의 Pseudocode 탭이 기다리게 됩니다.

- [x] 측정 도구: `tools/bench.py` — 분석·전체 디컴파일 시간, 함수별 상위 시간(함수당 시간 상한), goto·미해결 점프·`__asm` 수
- [x] `/usr/bin/grep`: 174개 함수 디컴파일 87.3초 → 43초대(goto 1723, 미해결 점프 8, `__asm` 18 그대로). 단독으로 처음 여는 경우 `main` 89초 → 27초, `sub_95b0` 32초 → 9초. 한 일: 필드 접근이 있는 매개변수만 호출자 조회, `narrow` 한 번의 순회(고정점 반복), DCE 사용 횟수 1회 계산 후 증감, 호출자 구조체 함수당 1회 생성, 피호출자가 요청한 호출자 구조체는 그 피호출자의 접근만 병합
- [x] 카나리 검사 찾기의 지수 시간(메모): mawk 전체 620초 → 62초, 시간 초과 2 → 0
- [x] 함수마다 최적화 SSA 한 번(호출자의 매개변수 추정과 `decompile_ir`가 공유), 나눗셈 판별식 표본 상한, IR 복사 가속: `/usr/bin/find` `main` 단독 20분 이상 → 14초, 처음 40개 함수 29.7초 → 12.1초, 테스트 바이너리 전체 69초 → 46초(출력 동일)
- [ ] 남은 비용: 구조체 스캔이 관련 함수마다 전체 `prepare`를 요구(`find` `main`은 54개 함수) — 전역 구조체는 상수 주소 접근이라 명령어 수준에서 모을 수 있음; `optimize`/`to_ssa` 자체(남은 시간의 약 60%)
- [x] 함수 하나가 오래 걸려도 GUI가 기다리지 않음: 다른 함수로 이동하면 실행 중인 디컴파일을 취소(취소 결과는 캐시하지 않음), 취소가 구조체·반환 폭 캐시의 재귀 가드를 "없음"으로 남기지 않음

## 대화형 UI 100% — 완료 (README 진행률의 기준 항목)

- [x] 리스팅·그래프·의사 코드·헥스, 이름·주석·변수 이름, xref, 검색, 패치, undo, 북마크, 구조체·C 타입 창, 같은 단어 강조, 섹션 창
- [x] 숫자 표시 형식(IDA H/R/B/O): 리스팅의 피연산자별, 의사 코드의 상수별 16진·10진·문자·2진·오프셋
- [x] 반복 주석(repeatable: 참조하는 곳마다 보이는 주석)
- [x] 이름 창(모든 이름 목록, 필터·이동)
- [x] 코드·데이터 정의(U 정의 해제, C 코드, D 데이터 크기 순환, A 문자열, `*` 배열), 함수 만들기·지우기(P / Ctrl+Delete), 함수 밖 메모리 리스팅
- [x] 호출 그래프(함수 하나의 호출자·피호출자 그래프)
- [x] 내비게이션 밴드(바이너리 전체를 코드·데이터·미분석으로 칠한 띠, 클릭 이동)

## 프로젝트·협업 100% — 완료 (README 진행률의 기준 항목)

- [x] 프로젝트 파일(모든 주석 상태·패치·바이너리 SHA-256) — IDB 대응. 분석 결과 자체는 저장하지 않고 열 때 다시 분석(수 초)
- [x] 스냅숏, 버전 기록(commit·log·diff·checkout) — IDA Teams의 버전 관리 대응
- [x] 다른 분석가의 프로젝트 병합(충돌 보고, 우리/그쪽 우선)
- [x] 함수 메타데이터 공유(위치 독립 지문, push/pull, 파일·서버 저장소) — Lumina 대응

## 스크립팅·확장 100% — 완료 (README 진행률의 기준 항목)

- [x] Python API — GUI에서 하는 모든 편집과 조회(메모리·섹션·명령·xref·호출 그래프·데이터 정의·함수 편집·Lumina·버전 기록), 레퍼런스 자동 생성과 최신 여부 테스트
- [x] GUI 콘솔, 스크립트 파일 실행(Alt+F7·최근 목록), 배치 실행(`relic script`)
- [x] 플러그인: 메뉴 동작·단축키, 훅(리스팅 줄·분석·커서·편집·디버거 정지·의사 코드)
- [x] SDK 대응 확장점: 플러그인 파일 로더·프로세서 모듈(명령 디코더)·의사 코드 훅, GUI와 CLI 모두. 리프터(디컴파일러 아키텍처)는 확장점 없음

## 라이브러리 식별 100% — 완료 (README 진행률의 기준 항목)

- [x] FLIRT 방식 시그니처: 정적 라이브러리에서 생성(`relic sigs build`), x86-64·ARM/Thumb·AArch64·MIPS·RISC-V, 별칭(공개 이름)·IFUNC 스텁
- [x] Lumina 대응 함수 메타데이터 공유
- [x] C++ 런타임(libstdc++·libgcc) 시그니처, 정적(local) 함수, 생성자·소멸자 변형(C1/C2, D1/D2)을 한 이름으로
- [x] 코드가 같은 함수 구분: 참조하는 대상으로 후보를 함께 좁힘, 이름 붙은 함수가 참조하는 함수(짧아서 혼자 못 맞추는 것)에 이름 전파
- [x] 데이터 테이블(vtable·함수 포인터 표 — glibc `__io_vtables`): 시그니처 파일에 슬롯 저장, 참조로 위치를 찾아 슬롯의 함수(호출되지 않는 가상 메서드도 함수로 만들어) 이름 붙임
- [x] 설치된 툴체인에서 시그니처 자동 생성(`relic sigs build --system`, File 메뉴), 식별한 라이브러리·버전·파일 형식에 맞는 세트 선택
- [x] 컴파일러·런타임 식별(GCC/clang/MSVC(Rich 헤더)/MinGW/rustc/Go 버전, glibc(필요 버전)/musl/msvcrt/ucrt, 정적·동적, C/C++/Rust/Go)
- [x] PE: COFF 정적 라이브러리(MinGW libmingwex·libmingw32·libmsvcrt·libgcc·시작 객체) 시그니처, x86-64·i686
- [x] RISC-V 링커 완화(relaxation) 모델링: `call` → `jal`/`c.j`, 주소를 만드는 auipc/lui 삭제(쓰는 명령의 기준 레지스터는 gp/tp로), TLS add 삭제, 정렬 nop 삭제
- [x] GUI 시그니처 창(File ▸ Library signatures, `Shift+F5`): 세트 목록(라이브러리·버전·아키텍처·형식·시그니처 수), 이 바이너리에 맞는 세트, 세트별 이름 붙인 수, 적용·이름 되돌리기·파일 추가·툴체인에서 생성

## P1 — 프로세서 100%까지 (README 80%)

IDA의 60여 개 CPU 계열 전부가 아니라, 리버싱·포너블·펌웨어에서 실제로 만나는 계열을 기준으로 삼습니다.

- [x] 분석·디컴파일: x86, x86-64, ARM/Thumb, AArch64, RISC-V RV64GC
- [x] MIPS32 little/big-endian(o32), MIPS64(n64: `d...` 명령, 32비트 연산의 부호 확장, `a4`-`a7` 인자, `.gpdword` 점프 테이블, `$t9`로 만드는 `_gp`), qemu로 디버깅
- [x] RISC-V RV32GC(ILP32D): XLEN을 매개변수로 한 리프터(FPR은 64비트 그대로), non-PIC `lui` 점프 테이블·절대 주소 항목, fa0-fa7 다음의 double을 정수 레지스터 쌍(`a0:a1`)으로(피호출자·호출 지점·가변 인자의 짝수 정렬 쌍), `fsd` 뒤 두 `lw`로 읽는 반쪽, double 슬롯 안의 워드 접근(`((int *)&var)[1]`), qemu-riscv32 디버깅; RV32 libc가 없어 테스트는 자립형 바이너리·재배치 객체와 자체 최소 런타임(`tests/src/rv32rt.c`)으로 qemu에서 실행
- [x] PowerPC 32비트(SysV, 빅 엔디언)·PowerPC64(ELFv2 리틀 엔디언): 리프터(명령 필드에서 직접 해독, CR 필드·record 형식·ctr·carry), PLT 호출 스텁(`.text`의 스텁, PIE는 호출자의 r30으로), ctr 점프 테이블, TOC·로컬 진입점, 스택 보호값(스레드 포인터), 부동소수점(FPR은 항상 double 형태, 단정밀도 연산·`0x43300000` 정수→double 관용구·VSX 스칼라·POWER9 `lxsd`), 위치로 정해지는 ELFv2 인자 순서, stripped `main`(r8의 시작 정보 블록), qemu 디버깅
- [ ] PowerPC64 ELFv1(빅 엔디언, 함수 디스크립터 `.opd`)
- [ ] 디스어셈블만: capstone이 아는 나머지(SPARC, SystemZ, M68K, SH, TriCore, BPF, WASM 등)

## P1 — 파일 포맷 100%까지 (README 100%)

- [x] ELF(실행·공유·정적), PE(import/export/COFF 심볼/.pdata), RAW
- [x] ELF 재배치 객체(`.o`): 섹션 배치, 재배치 적용(x86-64·x86·AArch64·ARM/Thumb·MIPS·RISC-V), 외부 심볼은 import 스텁, GOT 슬롯
- [x] COFF 객체(`.obj`/MinGW `.o`, x64·x86)
- [x] 정적 라이브러리 멤버(`lib.a:member.o`, 지정 없으면 첫 객체)
- [x] Intel HEX·Motorola S-record(시작 주소 레코드, Cortex-M 벡터 테이블의 리셋 핸들러)
- [x] ELF 코어 덤프(메모리·레지스터·시그널·매핑된 파일, 디스크에 남은 실행 파일의 심볼·툴체인)
- [x] PE: TLS 콜백, 리소스·버전 정보, 지연 import(데이터 디렉터리 13 또는 MinGW 서술자 심볼), .NET 감지(CLR 헤더·메타데이터 런타임 버전), 디버그 디렉터리(PDB 경로·GUID·age)
- [x] RAW 펌웨어의 적재 주소 추정(문자열 포인터 상관, Cortex-M 벡터 테이블; `--base auto`, `relic info`에 후보)
- [x] Mach-O: 실행 파일·dylib·번들(32/64비트), 유니버설 파일(슬라이스 선택), 세그먼트·섹션, nlist 심볼, 간접 심볼 표로 import(`__stubs`·`__la_symbol_ptr`·`__got`, 2단계 이름공간의 라이브러리), `LC_MAIN`/`LC_UNIXTHREAD` 진입점, `LC_FUNCTION_STARTS`, UUID·플랫폼·rpath, checksec(PIE·NX·카나리·코드 서명·암호화·`__RESTRICT`·ARC), Apple arm64 가변 인자(스택)
- [x] Mach-O 재배치 객체(`MH_OBJECT`): 섹션을 기준 주소에서부터, 외부 심볼은 스텁·GOT 슬롯, 재배치 적용(x86-64 BRANCH·SIGNED·GOT_LOAD·UNSIGNED, arm64 BRANCH26·PAGE21·PAGEOFF12·GOT_LOAD·ADDEND), 어셈블러 지역 레이블(`ltmp`·`l_`)은 이름 아님
- [x] Mach-O chained fixups(`LC_DYLD_CHAINED_FIXUPS`): 체인을 따라 rebase는 실제 주소로 읽히게, bind는 import 이름으로(포인터 형식 64·64_OFFSET·32·arm64e 계열)
- [x] Objective-C 메타데이터(`relic/loader/objc.py`): 클래스·상위 클래스·메서드(포인터 목록과 상대 오프셋 목록)·ivar·속성·카테고리, 메서드 구현에 `-[Class sel:]` 이름(stripped에서도), selector·class 참조 슬롯 이름; 의사 코드에서 `objc_msgSend`를 `[recv sel:arg]`로(셀렉터의 `:` 수로 인자, 레지스터에 담아 둔 objc_msgSend·꼬리 호출도), `objc_alloc_init` 등은 `[[Cls alloc] init]`, 메서드는 `self`·`_cmd`, 반환 형식은 타입 인코딩에서, ivar 접근은 `self->ivar`

## P1 — 디버거 100%까지 (README 100%)

- [x] 로컬: 실행·단계 실행·중단점(조건·활성화·적중 횟수·라이브러리 함수)·하드웨어 watchpoint·레지스터/메모리 보기·편집·telescope·vmmap·백트레이스·콘솔·힙 뷰·PIE 슬라이드
- [x] 원격 gdbserver(`host:port`)
- [x] 다른 아키텍처 프로그램을 qemu-user의 gdb 스텁으로(ARM·AArch64·MIPS·RISC-V, 자동 선택), 입출력·환경 변수
- [x] 실행 중인 프로세스에 붙기·떼기
- [x] 실행 옵션: 환경 변수·작업 디렉터리·입력 파일
- [x] 스레드: 목록·전환·스레드별 레지스터/백트레이스(Threads 창)
- [x] 공유 라이브러리(모듈) 목록(Modules 창), 라이브러리 적재 시 정지
- [x] 시그널: 정지·전달 정책(Debug ▸ Signals, 세션마다 유지), 정지 이유에 시그널 정보
- [x] 추적: 명령 단위 추적 기록(Debug ▸ Trace instructions), 리스팅에 실행된 명령 표시
- [x] Windows(PE) 대상: Windows의 gdbserver.exe로 원격, Linux에서는 wine으로 자동 실행(win32·win64, 입출력·환경 변수·DLL 모듈)

## P1 — 자동 분석 100%까지 (README 70%)

기준: stripped 실제 바이너리(coreutils·grep·gzip·bash)에서 `.eh_frame`의 함수 진입점을 정답으로 한 함수 찾기 재현율, 해석되지 않은 간접 점프 수.

- [x] 함수 찾기: 재귀 하강, 심볼·`.init_array`·PE `.pdata`·Mach-O `LC_FUNCTION_STARTS`, 프롤로그 스캔
- [x] `.eh_frame` FDE를 함수 목록으로(첫 CFA 행이 진입 상태인 것만: `.cold` 조각·PLT 제외): 다른 함수 뒤의 시드, 함수 경계(그 시작으로 흘러 들어가지 않음 — 돌아오지 않는 내부 호출 뒤), 그 시작으로의 점프는 꼬리 호출. gcc `.cold` 심볼은 함수 아님. bash 재현율 99.9%(PLT 제외 전부)
- [x] x86 점프 테이블: 테이블을 읽는 레지스터의 `lea`(가까이 있는 다른 `lea`가 아니라), 루프 밖으로 끌어낸 기준 레지스터(함수 시작부터 순서대로), 음수 case(`cmp x, -5; jb`: 항목 5개). bash의 해석 안 된 간접 점프 103 → 12(남은 것은 꼬리 호출)
- [x] 레지스터를 거친 꼬리 호출: 에필로그 뒤 `jmp rax`(함수 포인터), import를 담아 둔 레지스터(`jmp rbx` = objc_msgSend), 식으로 전달된 인자
- [ ] 돌아오지 않는 내부 함수 추론(`.eh_frame` 없는 바이너리)
- [ ] 간접 호출 대상(가상 함수 테이블·함수 포인터 표)
- [ ] 코드 사이 데이터 감지(ARM 리터럴 풀 밖, 손으로 쓴 어셈블리)
- [ ] 큰 바이너리 분석 속도(bash 약 15초)

## P1 — 타입 시스템 100%까지 (README 85%)

- [x] 로컬 타입(구조체·공용체·비트필드·열거형·typedef·함수 원형, C 헤더 가져오기, 편집 창), 구조체 자동 복원
- [x] 타입 라이브러리: libc(구조체, 대상 ABI 레이아웃)
- [x] 호출을 통한 타입 전파: 라이브러리·가져온·사용자 원형 → 인자·결과·주소를 넘긴 스택 구조체
- [x] 타입 라이브러리: Windows API(PE: kernel32·advapi32·user32·ws2_32 원형, 구조체 18개, 32/64비트 레이아웃)
- [ ] 구조체 값 전달 인자·반환(ABI별 레지스터/스택 배치)

## P1 — 출력 품질

- [x] libc 인자·결과 타입으로 매개변수·변수 타입 지정(`strlen(a1)` → `char *a1`, `malloc(n)` → `size_t n`, `void *` 결과, `fopen` → `FILE *`, 상수 형식 문자열의 `%s`/`%p`/`%zu`, 식 안의 호출 포함) — 메모리 접근으로 복원한 포인터 타입이 우선
- [ ] goto 줄이기 — 기준선(bench): true 153, cat 375, gzip 911, grep 1861. 구조화·출력 정확성은 무작위 CFG 실행 비교 테스트(`test_random_cfgs_run_like_the_cfg`: 구조화 트리, `test_emitted_c_runs_like_the_cfg`: 출력한 C를 gcc로 컴파일해 실행)로 지킴: 줄이는 변경도 이 테스트를 통과해야 함
  - [ ] 큰 상태 기계 함수의 goto(gnulib `quotearg`, gzip deflate/inflate) — 조건 기반 구조화 검토

## P1 — 분석

- [x] 정적 링크된 stripped 바이너리의 라이브러리 함수 이름 찾기(시그니처) — `relic/analysis/libsigs.py`, `relic sigs build`, File ▸ Apply library signatures
  - [ ] 남은 일: 코드가 같은 짧은 스텁 중 참조로도 구분되지 않는 것(`__chk_fail`/`__fortify_fail` 류, Thumb `fopen`처럼 어셈블러가 푼 분기 하나뿐인 함수), stripped 정적 MIPS의 `main`(`_start`가 GOT로 `__libc_start_main` 호출 — `bal`로 만든 `gp`를 리프터가 풀지 못함)
- [x] capstone 일괄 디코딩: 캐시에 없을 때 x86 명령 8개까지 한 번에 디코딩해 캐시(정적 바이너리 분석 약 9% 단축). 남은 비용은 capstone 파이썬 바인딩의 명령당 객체·detail 생성(약 70µs) — detail 없이(`disasm_lite`) 디코딩하고 필요할 때만 detail을 만드는 방법은 명령의 약 37%에만 해당해 보류

## P2

- [ ] 부동소수점: x87(`fld`/`fstp`, 32비트 cdecl의 `double` 반환), `unsigned` ↔ `double` 변환 관용구(`cvtsi2sd` + 보정 분기)
- [ ] C 헤더: 매크로 상수(`#define`) 이름으로 상수 출력(어느 인자에 쓰이는지 알아야 함), 구조체 by-value 인자, MS ABI 비트필드 레이아웃
- [ ] RV32(ILP32) 리프터
- [ ] ARM 데이터 영역을 코드로 잘못 읽은 경우(coprocessor 명령 등) 감지
