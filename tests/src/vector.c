/* Loops gcc -O3 vectorizes (SSE2): packed integer and float arithmetic, reductions. */
#include <stdio.h>
#include <stdlib.h>
__attribute__((noinline)) void add(int *a, const int *b, int n) { for (int i = 0; i < n; i++) a[i] += b[i]; }
__attribute__((noinline)) int sum(const int *a, int n) { int s = 0; for (int i = 0; i < n; i++) s += a[i]; return s; }
__attribute__((noinline)) void scale(float *a, float k, int n) { for (int i = 0; i < n; i++) a[i] *= k; }
__attribute__((noinline)) int count(const char *s, int n, char c) { int k = 0; for (int i = 0; i < n; i++) k += s[i] == c; return k; }
int main(int argc, char **argv) {
    int n = argc * 16; int *a = calloc(n, 4), *b = calloc(n, 4); float *f = calloc(n, 4);
    for (int i = 0; i < n; i++) { b[i] = i; f[i] = i; }
    add(a, b, n); scale(f, 2.5f, n);
    printf("%d %f %d\n", sum(a, n), f[3], count(argv[0], 5, 'a'));
    return 0;
}
