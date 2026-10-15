/* library calls the built-in table does not know: bundled prototypes give their arguments */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>

#define NI __attribute__((noinline))

NI void log_msg(int level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (level > 1)
        vfprintf(stderr, fmt, ap);
    va_end(ap);
}

NI int serve(unsigned short port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0)
        return -1;
    listen(s, 5);
    return s;
}

NI void *region(size_t n)
{
    void *p = mmap(0, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mprotect(p, n, PROT_READ);
    return p;
}

NI unsigned long parse_num(const char *s)
{
    char *end;
    unsigned long v = strtoul(s, &end, 16);
    return *end ? 0 : v;
}

NI void shell(char *user)
{
    log_msg(2, user);                               /* format string bug through a wrapper */
    log_msg(1, "user %s\n", user);
    execl("/bin/sh", "sh", "-c", "id", (char *)0);
}

int main(int argc, char **argv)
{
    char *line = 0;
    size_t cap = 0;
    if (getline(&line, &cap, stdin) > 0)
        printf("%lu\n", parse_num(line));
    region(4096);
    if (argc > 2)
        shell(argv[1]);
    return serve(8080) < 0;
}
