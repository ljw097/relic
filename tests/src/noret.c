/* Function discovery without `.eh_frame` (built -fno-asynchronous-unwind-tables): functions that
 * never return (gcc lays the next function right after a call of one), tail calls of functions
 * nothing else reaches, functions only reached through a table of pointers in data. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) static void fatal(const char *msg)
{
    fprintf(stderr, "fatal: %s\n", msg);
    exit(2);
}

__attribute__((noinline)) static void usage(int code)
{
    if (code)
        fatal("bad usage");
    fatal("usage: noret N");
}

__attribute__((noinline)) int parse(const char *s)
{
    char *end;
    long v = strtol(s, &end, 10);
    if (*end)
        fatal(s);
    return (int)v;
}

__attribute__((noinline)) static int change_case(const char *s, int upper)
{
    int n = 0;
    for (; *s; s++)
        n += upper ? (*s >= 'a' && *s <= 'z') : (*s >= 'A' && *s <= 'Z');
    printf("%d\n", n);
    return n;
}

__attribute__((noinline)) int upcase(const char *s) { return change_case(s, 1); }
__attribute__((noinline)) int downcase(const char *s) { return change_case(s, 0); }

static int cb_len(const char *s) { return (int)strlen(s); }
static int cb_first(const char *s) { return s[0]; }
static int cb_sum(const char *s) { int n = 0; while (*s) n += *s++; return n; }

struct op { const char *name; int (*fn)(const char *); };
struct op ops[] = { {"len", cb_len}, {"first", cb_first}, {"sum", cb_sum}, {"up", upcase}, {"down", downcase} };

int main(int argc, char **argv)
{
    if (argc < 3)
        usage(argc);
    int k = parse(argv[1]);
    if (k < 0 || k >= (int)(sizeof ops / sizeof ops[0]))
        usage(0);
    printf("%s %d\n", ops[k].name, ops[k].fn(argv[2]));
    return 0;
}
