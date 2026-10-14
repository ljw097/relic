/* Library calls that say what their arguments and results are (tests/test_libtypes.py). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) size_t name_size(const char *s) { return strlen(s) + 1; }

__attribute__((noinline)) void *filled(size_t n, int c)
{
    void *p = malloc(n);
    if (p)
        memset(p, c, n);
    return p;
}

__attribute__((noinline)) int show(FILE *fp, const char *name, int v) { return fprintf(fp, "%s=%d\n", name, v); }

__attribute__((noinline)) char *joined(const char *a, const char *b)
{
    char *r = malloc(strlen(a) + strlen(b) + 1);
    strcpy(r, a);
    strcat(r, b);
    return r;
}

__attribute__((noinline)) long count_lines(const char *path)
{
    FILE *fp = fopen(path, "r");
    long n = 0;
    int c;
    if (!fp)
        return -1;
    while ((c = fgetc(fp)) != EOF)
        n += c == '\n';
    fclose(fp);
    return n;
}

int main(int argc, char **argv)
{
    char *x = joined(argv[0], "-x");
    show(stdout, x, (int)name_size(x));
    free(filled((size_t)argc, 0));
    free(x);
    return argc > 1 ? (int)count_lines(argv[1]) : 0;
}
