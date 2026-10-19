/* libc flag arguments relic names after their header constants (tests/test_cheader.py) */
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#define MODE_READ 1
#define MODE_WRITE 2
#define MODE_EXEC 4

__attribute__((noinline)) int set_mode(int mode) { return mode * 3 + 1; }

void *map(void) { return mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); }

int create(const char *path) { return open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644); }

long rewind_fd(int fd) { return lseek(fd, 0, SEEK_END); }

int main(int argc, char **argv) { return set_mode(MODE_READ | MODE_EXEC) + create(argv[1]) + (map() != 0); }
