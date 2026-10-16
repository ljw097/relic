/* A program to debug wherever it runs: prints an environment variable, echoes a line of
   input, calls work() (a breakpoint target) and exits. */
#include <stdio.h>
#include <stdlib.h>

int counter = 3;

int work(int x)
{
    counter += x;
    return counter * 2;
}

int main(int argc, char **argv)
{
    char buf[32];
    const char *v = getenv("RELIC_T");
    printf("hello %s\n", v ? v : "-");
    fflush(stdout);
    if (fgets(buf, sizeof buf, stdin))
        printf("got %s", buf);
    printf("r=%d\n", work(argc));
    return 0;
}
