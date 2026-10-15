"""Prototypes of common C library / POSIX functions, as a header the C declaration parser reads.

`sigs.lookup` falls back to these for imports its own table (which also knows the format
arguments of the printf / scanf families) does not list: how many arguments a call takes,
their C types and the result type. Typedefs stand for what glibc uses on Linux.
"""

LIBC_H = r"""
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned int mode_t;
typedef unsigned int socklen_t;
typedef unsigned short sa_family_t;
typedef long clock_t;
typedef unsigned long nfds_t;
typedef int sig_atomic_t;
typedef void *sighandler_t;
typedef unsigned long pthread_t;

/* stdlib */
long strtol(const char *s, char **end, int base);
unsigned long strtoul(const char *s, char **end, int base);
long long strtoll(const char *s, char **end, int base);
unsigned long long strtoull(const char *s, char **end, int base);
long long atoll(const char *s);
int abs(int x);
long labs(long x);
void qsort(void *base, size_t n, size_t size, void *cmp);
void *bsearch(const void *key, const void *base, size_t n, size_t size, void *cmp);
char *getenv(const char *name);
int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);
int putenv(char *s);
int atexit(void *fn);
void *aligned_alloc(size_t align, size_t size);
int posix_memalign(void **p, size_t align, size_t size);
void *reallocarray(void *p, size_t n, size_t size);
char *realpath(const char *path, char *resolved);
int mkstemp(char *tmpl);
long random(void);
void srandom(unsigned int seed);
int rand_r(unsigned int *seed);

/* strings and memory */
char *strndup(const char *s, size_t n);
size_t strnlen(const char *s, size_t max);
int strcasecmp(const char *a, const char *b);
int strncasecmp(const char *a, const char *b, size_t n);
char *strtok(char *s, const char *delim);
char *strtok_r(char *s, const char *delim, char **save);
char *strsep(char **s, const char *delim);
size_t strspn(const char *s, const char *accept);
size_t strcspn(const char *s, const char *reject);
char *strpbrk(const char *s, const char *accept);
char *strerror(int err);
size_t strlcpy(char *d, const char *s, size_t n);
char *stpcpy(char *d, const char *s);
void *memchr(const void *s, int c, size_t n);
void *memrchr(const void *s, int c, size_t n);
void *mempcpy(void *d, const void *s, size_t n);
void *memmem(const void *h, size_t hn, const void *n, size_t nn);
int toupper(int c);
int tolower(int c);
int isalpha(int c);
int isdigit(int c);
int isspace(int c);
int isalnum(int c);
int isprint(int c);
int isxdigit(int c);
int isupper(int c);
int islower(int c);

/* stdio */
FILE *fdopen(int fd, const char *mode);
FILE *freopen(const char *path, const char *mode, FILE *f);
int fseek(FILE *f, long off, int whence);
long ftell(FILE *f);
void rewind(FILE *f);
int feof(FILE *f);
int ferror(FILE *f);
int fileno(FILE *f);
int ungetc(int c, FILE *f);
ssize_t getline(char **line, size_t *n, FILE *f);
ssize_t getdelim(char **line, size_t *n, int delim, FILE *f);
int remove(const char *path);
int rename(const char *a, const char *b);
FILE *tmpfile(void);
FILE *popen(const char *cmd, const char *mode);
int pclose(FILE *f);
void clearerr(FILE *f);
int puts_unlocked(const char *s);

/* unistd / fcntl / files */
int openat(int dirfd, const char *path, int flags, ...);
int creat(const char *path, mode_t mode);
off_t lseek(int fd, off_t off, int whence);
ssize_t pread(int fd, void *buf, size_t n, off_t off);
ssize_t pwrite(int fd, const void *buf, size_t n, off_t off);
int dup(int fd);
int dup2(int a, int b);
int pipe(int *fds);
int unlink(const char *path);
int rmdir(const char *path);
int mkdir(const char *path, mode_t mode);
int chdir(const char *path);
char *getcwd(char *buf, size_t n);
int access(const char *path, int mode);
int chmod(const char *path, mode_t mode);
int chown(const char *path, uid_t uid, gid_t gid);
int truncate(const char *path, off_t n);
int ftruncate(int fd, off_t n);
int fsync(int fd);
int isatty(int fd);
ssize_t readlink(const char *path, char *buf, size_t n);
int symlink(const char *target, const char *path);
int link(const char *a, const char *b);
int fcntl(int fd, int cmd, ...);
int ioctl(int fd, unsigned long req, ...);
int stat(const char *path, struct stat *st);
int fstat(int fd, struct stat *st);
int lstat(const char *path, struct stat *st);
void *opendir(const char *path);
struct dirent *readdir(void *dir);
int closedir(void *dir);

/* processes */
pid_t fork(void);
pid_t vfork(void);
pid_t getpid(void);
pid_t getppid(void);
uid_t getuid(void);
uid_t geteuid(void);
gid_t getgid(void);
gid_t getegid(void);
int setuid(uid_t uid);
int setgid(gid_t gid);
int setresuid(uid_t r, uid_t e, uid_t s);
int setresgid(gid_t r, gid_t e, gid_t s);
int execve(const char *path, char **argv, char **envp);
int execv(const char *path, char **argv);
int execvp(const char *file, char **argv);
int execl(const char *path, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
pid_t waitpid(pid_t pid, int *status, int options);
pid_t wait(int *status);
int kill(pid_t pid, int sig);
int raise(int sig);
unsigned int alarm(unsigned int seconds);
int usleep(unsigned int usec);
int pause(void);
sighandler_t signal(int sig, sighandler_t handler);
int sigaction(int sig, const struct sigaction *act, struct sigaction *old);
long syscall(long number, ...);
int prctl(int option, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5);
int chroot(const char *path);
int daemon(int nochdir, int noclose);

/* memory mapping */
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
int munmap(void *addr, size_t len);
int mprotect(void *addr, size_t len, int prot);
void *sbrk(long inc);
int brk(void *addr);

/* time */
clock_t clock(void);
int gettimeofday(struct timeval *tv, void *tz);
int nanosleep(const struct timespec *req, struct timespec *rem);
char *ctime(const time_t *t);
struct tm *localtime(const time_t *t);
struct tm *gmtime(const time_t *t);
time_t mktime(struct tm *tm);
size_t strftime(char *s, size_t n, const char *fmt, const struct tm *tm);

/* sockets */
int socket(int domain, int type, int protocol);
int bind(int fd, const struct sockaddr *addr, socklen_t len);
int listen(int fd, int backlog);
int accept(int fd, struct sockaddr *addr, socklen_t *len);
int connect(int fd, const struct sockaddr *addr, socklen_t len);
ssize_t send(int fd, const void *buf, size_t n, int flags);
ssize_t recv(int fd, void *buf, size_t n, int flags);
ssize_t sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *to, socklen_t len);
ssize_t recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *from, socklen_t *len);
int setsockopt(int fd, int level, int name, const void *val, socklen_t len);
int getsockopt(int fd, int level, int name, void *val, socklen_t *len);
int shutdown(int fd, int how);
unsigned short htons(unsigned short x);
unsigned short ntohs(unsigned short x);
unsigned int htonl(unsigned int x);
unsigned int ntohl(unsigned int x);
int inet_pton(int af, const char *src, void *dst);
const char *inet_ntop(int af, const void *src, char *dst, socklen_t n);
unsigned int inet_addr(const char *s);
struct hostent *gethostbyname(const char *name);
int select(int n, void *r, void *w, void *e, struct timeval *timeout);
int poll(struct pollfd *fds, nfds_t n, int timeout);

/* dynamic loading, threads */
void *dlopen(const char *path, int flags);
void *dlsym(void *handle, const char *name);
int dlclose(void *handle);
char *dlerror(void);
int pthread_create(pthread_t *t, const void *attr, void *fn, void *arg);
int pthread_join(pthread_t t, void **ret);
int pthread_mutex_lock(void *m);
int pthread_mutex_unlock(void *m);

/* misc */
int seccomp_load(void *ctx);
void *seccomp_init(unsigned int action);
int seccomp_rule_add(void *ctx, unsigned int action, int syscall, unsigned int n, ...);
void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function);
int *__errno_location(void);
void __cxa_finalize(void *d);
"""

__all__ = ["LIBC_H"]
