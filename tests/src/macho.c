/* A small macOS program for the Mach-O loader: libc declared here (no macOS SDK on the build
   machine), linked against tests/src/libSystem.tbd. */
typedef unsigned long size_t;
int printf(const char *, ...);
int puts(const char *);
void *malloc(size_t);
void free(void *);
char *gets(char *);
int system(const char *);
void exit(int);

int counter = 7;
const char *names[] = {"zero", "one", "two"};

int classify(int x)
{
    switch (x) {
    case 0: return 10;
    case 1: return 21;
    case 2: return 32;
    case 3: return 43;
    case 4: return 54;
    case 5: return 65;
    default: return -1;
    }
}

int checksum(const char *s)
{
    int h = 0;
    while (*s)
        h = h * 31 + *s++;
    return h % 100000;
}

void win(void)
{
    system("/bin/sh");
}

void vuln(void)
{
    char buf[64];
    puts("name?");
    gets(buf);
    printf("hello %s (%d)\n", buf, checksum(buf));
}

int main(int argc, char **argv)
{
    char *p = malloc(32);
    if (!p)
        exit(1);
    counter += classify(argc);
    printf("%s %d\n", names[argc % 3], counter);
    vuln();
    free(p);
    return 0;
}
