/* A heap with used, tcache and free (unsorted) chunks for the debugger's heap view
   (tests/test_heap.py). */
#include <stdlib.h>
#include <string.h>

#define NI __attribute__((noinline))

NI void stop_here(void *keep)
{
    __asm__ volatile("" : : "r"(keep) : "memory");
}

int main(void)
{
    char *a = malloc(24), *b = malloc(40), *c = malloc(0x500);
    char *d = malloc(24), *e = malloc(24), *guard = malloc(24);
    strcpy(a, "AAAABBBB");
    free(b);
    free(d);
    free(e);
    free(c);              /* too big for the tcache: unsorted, a free chunk */
    stop_here(a);
    stop_here(guard);
    return 0;
}
