/* declarations shared by types.c and the header-import tests */
#ifndef TYPES_H
#define TYPES_H
#include <stddef.h>

enum state { IDLE, RUNNING, STOPPED = 5, FAILED };
typedef enum { OPT_VERBOSE = 1, OPT_FORCE = 2, OPT_DRY = 4, OPT_ALL = 8 } options_t;

struct header {
    unsigned short len;
    unsigned char kind;
};

typedef struct job {
    struct job *next;
    const char *name;
    struct header hdr;
    enum state state;
    unsigned int opts;
    long budget;
    int prio[3];
} job_t;

#define MAX_PRIO 9
struct packet {
    unsigned int version : 4;
    unsigned int ihl : 4;
    unsigned char tos;
    unsigned short frag : 13, flags : 3;
    int ttl;
};

int run_job(job_t *j, enum state target, options_t opts);
const char *state_name(enum state s);
int count_running(struct job *head);
void add_option(job_t *j, options_t o);
int packet_len(struct packet *p);

#endif
