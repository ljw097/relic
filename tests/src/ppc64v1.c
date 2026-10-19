/* PowerPC64 ELFv1 (big-endian, function descriptors in .opd), freestanding: built with clang + ld.lld. */
static int square(int x) { return x * x; }
int (*fp)(int) = square;
int helper(int a, int b) { return fp(a) + b * 3; }
void _start(void) { volatile int r = helper(5, 7); (void)r; for (;;) ; }
