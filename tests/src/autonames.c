/* Names the analysis suggests (tests/test_autonames.py): stripped, its functions are named
   from what their code shows, and the decompiler's variables from how they are used. */
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NI __attribute__((noinline))

NI static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s FILE [WORD]\n", prog);
    exit(2);
}

NI static void fatal(const char *msg)
{
    fprintf(stderr, "error: %s\n", msg);
    exit(1);
}

NI static void *xmalloc(size_t n)
{
    void *p = malloc(n);
    if (!p) {
        perror("malloc");
        abort();
    }
    return p;
}

NI static void say(const char *s) { puts(s); }      /* -O2: `jmp puts`, a thunk */

struct table { int n; int *v; };

NI static int table_insert(struct table *t, int x)
{
    assert(t != NULL && t->n < 100);
    t->v[t->n++] = x;
    return t->n;
}

NI static int count_lines(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "count_lines: cannot open %s\n", path);
        return -1;
    }
    char buf[512];
    int n = 0;
    ssize_t r;
    while ((r = read(fd, buf, sizeof buf)) > 0)
        for (ssize_t i = 0; i < r; i++)
            if (buf[i] == '\n')
                n++;
    close(fd);
    return n;
}

NI static size_t total_length(char **words, int count)
{
    size_t total = 0;
    for (int i = 0; i < count; i++)
        total += strlen(words[i]);
    return total;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        usage(argv[0]);
    const char *home = getenv("HOME");
    struct table t = {0, xmalloc(400)};
    for (int i = 0; i < 10; i++)
        table_insert(&t, i * i);
    int lines = count_lines(argv[1]);
    if (lines < 0)
        fatal("no input");
    say(home ? home : "?");
    printf("%d %d %zu\n", lines, t.n, total_length(argv, argc));
    return 0;
}
