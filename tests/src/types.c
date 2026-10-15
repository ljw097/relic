#include <stdio.h>
#include <stdlib.h>
#include "types.h"

#define NI __attribute__((noinline))

NI const char *state_name(enum state s)
{
    switch (s) {
    case IDLE: return "idle";
    case RUNNING: return "running";
    case STOPPED: return "stopped";
    case FAILED: return "failed";
    }
    return "?";
}

NI void add_option(job_t *j, options_t o)
{
    j->opts |= o;
}

NI int run_job(job_t *j, enum state target, options_t opts)
{
    if (j->state == FAILED)
        return -1;
    if (opts & OPT_DRY) {
        printf("would move %s to %s\n", j->name, state_name(target));
        return 0;
    }
    j->state = target;
    j->hdr.len = (unsigned short)(j->hdr.len + 1);
    if (opts & OPT_VERBOSE)
        printf("%s: %s (%u)\n", j->name, state_name(j->state), j->hdr.kind);
    return j->prio[0] + j->prio[2];
}

NI int count_running(struct job *head)
{
    int n = 0;
    for (struct job *j = head; j; j = j->next)
        if (j->state == RUNNING)
            n++;
    return n;
}

int main(int argc, char **argv)
{
    job_t a = {0}, b = {0};
    a.name = "a";
    b.name = "b";
    a.next = &b;
    a.prio[0] = 3;
    add_option(&a, OPT_FORCE);
    run_job(&a, RUNNING, OPT_VERBOSE | OPT_DRY);
    run_job(&b, STOPPED, OPT_VERBOSE);
    printf("%d %s\n", count_running(&a), state_name((enum state)(argc + 3)));
    return 0;
}
