/* a call relic cannot tell does not return, then the literal pool (tests/test_arm.py) */
#include <stdio.h>
#include <stdlib.h>
void (*volatile quit)(int) = exit;
__attribute__((noinline)) void fatal(const char *m) { puts(m); quit(1); }
__attribute__((noinline)) int check(int x) {
    if (x > 100) { fatal("too big: a long message here"); __builtin_unreachable(); }
    printf("value %d %d\n", x, 0x12345678);
    return x * 3;
}
int main(int argc, char **argv) { return check(argc); }
