/* Just enough of a C library to run the RV32 test programs under qemu-riscv32: the RV64 cross
   compiler ships no RV32 libc. Output through write(2); %s %d %ld %u %x in formats (what the
   programs print), the rest of a format copied as is; lines of input through read(2). Build with
   -fno-math-errno, so that the math functions below are the instructions. */
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

static long sys3(long n, long a, long b, long c)
{
    register long a0 __asm__("a0") = a, a1 __asm__("a1") = b, a2 __asm__("a2") = c, a7 __asm__("a7") = n;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a7) : "memory");
    return a0;
}

size_t strlen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

void *memcpy(void *d, const void *s, size_t n)
{
    unsigned char *p = d;
    const unsigned char *q = s;
    while (n--) *p++ = *q++;
    return d;
}

void *memset(void *d, int c, size_t n)
{
    unsigned char *p = d;
    while (n--) *p++ = (unsigned char)c;
    return d;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *p = a, *q = b;
    for (; n--; p++, q++)
        if (*p != *q) return *p - *q;
    return 0;
}

static void out(const char *s, size_t n) { sys3(64, 1, (long)s, (long)n); }

int puts(const char *s) { out(s, strlen(s)); out("\n", 1); return 0; }

FILE *stdin = (FILE *)0, *stdout = (FILE *)1, *stderr = (FILE *)2;
static char **environ_;

int fflush(FILE *f) { (void)f; return 0; }

char *fgets(char *s, int n, FILE *f)
{
    int k = 0;
    (void)f;
    while (k < n - 1 && sys3(63, 0, (long)(s + k), 1) == 1)
        if (s[k++] == '\n')
            break;
    s[k] = 0;
    return k ? s : NULL;
}

char *getenv(const char *name)
{
    size_t n = strlen(name);
    for (char **e = environ_; e && *e; e++)
        if (!memcmp(*e, name, n) && (*e)[n] == '=')
            return *e + n + 1;
    return NULL;
}

static void num(unsigned long v, int neg, unsigned base)
{
    char buf[24], *p = buf + sizeof buf;
    do { *--p = "0123456789abcdef"[v % base]; v /= base; } while (v);
    if (neg) *--p = '-';
    out(p, buf + sizeof buf - p);
}

static int vfmt(const char *f, va_list ap)
{
    for (; *f; f++) {
        if (*f != '%') { out(f, 1); continue; }
        f++;
        while (*f == 'l') f++;
        if (*f == 's') { const char *s = va_arg(ap, const char *); out(s, strlen(s)); }
        else if (*f == 'd') { long v = va_arg(ap, long); num(v < 0 ? -(unsigned long)v : (unsigned long)v, v < 0, 10); }
        else if (*f == 'u') num(va_arg(ap, unsigned long), 0, 10);
        else if (*f == 'x') num(va_arg(ap, unsigned long), 0, 16);
        else if (*f) out(f - 1, 2);
        else break;
    }
    return 0;
}

int printf(const char *f, ...) { va_list ap; va_start(ap, f); vfmt(f, ap); va_end(ap); return 0; }

int __printf_chk(int flag, const char *f, ...)
{
    va_list ap;
    (void)flag;
    va_start(ap, f);
    vfmt(f, ap);
    va_end(ap);
    return 0;
}

double sqrt(double x) { return __builtin_sqrt(x); }
float sqrtf(float x) { return __builtin_sqrtf(x); }
double fma(double a, double b, double c) { return __builtin_fma(a, b, c); }
float fmaf(float a, float b, float c) { return __builtin_fmaf(a, b, c); }
double fabs(double x) { return __builtin_fabs(x); }
float fabsf(float x) { return __builtin_fabsf(x); }

int main();

/* the kernel's (qemu's) initial stack: argc, argv[], NULL, envp[], NULL */
void rt_start(long *sp)
{
    int argc = (int)sp[0];
    char **argv = (char **)(sp + 1);
    environ_ = argv + argc + 1;
    sys3(93, main(argc, argv), 0, 0);   /* exit */
    for (;;) {}
}

__asm__(".globl _start\n_start:\n\tmv a0, sp\n\tcall rt_start\n");
