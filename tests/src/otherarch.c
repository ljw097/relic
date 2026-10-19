/* Built for the processors Relic disassembles but does not decompile (clang -c). */
int g;
static int sq(int x) { return x * x; }
int work(int a, int b) { int s = 0; for (int i = 0; i < a; i++) s += sq(i) ^ b; g = s; return s > 100 ? s : -s; }
int entry(int n) { return work(n, 3) + work(n + 1, 5); }
