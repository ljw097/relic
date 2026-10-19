/* A WebAssembly module (clang --target=wasm32): an exported function calling an imported one. */
int printf(const char *, ...);
static int sq(int x) { return x * x; }
__attribute__((export_name("work"))) int work(int a, int b) { int s = 0; for (int i = 0; i < a; i++) s += sq(i) ^ b; if (s > 100) printf("%d\n", s); return s; }
