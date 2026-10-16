/* An object file to load unlinked: a static helper, a global, a string through a static
   pointer and a library call -- all reached through relocations. */
#include <stdio.h>

int counter;
static const char *msg = "hello";

static int helper(int x)
{
    return x * 3 + counter;
}

int api(int a)
{
    counter += a;
    printf("%s %d\n", msg, helper(a));
    return counter;
}

int main(int c, char **v)
{
    return api(c) + helper(2);
}
