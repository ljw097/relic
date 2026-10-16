/* Threads, a signal and a loop to trace: two workers sleep until main is done with spin()
   and has raised SIGUSR1 (its handler prints a line). */
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

volatile int stop_here = 0;

void *worker(void *a)
{
    while (!stop_here)
        usleep(1000);
    return a;
}

void handler(int s)
{
    printf("caught %d\n", s);
    fflush(stdout);
}

int spin(int n)
{
    int t = 0;
    for (int i = 0; i < n; i++)
        t += i * 3;
    return t;
}

int main(void)
{
    pthread_t t[2];
    signal(SIGUSR1, handler);
    for (int i = 0; i < 2; i++)
        pthread_create(&t[i], 0, worker, 0);
    usleep(20000);
    printf("spin %d\n", spin(10));
    raise(SIGUSR1);
    stop_here = 1;
    for (int i = 0; i < 2; i++)
        pthread_join(t[i], 0);
    puts("done");
    return 0;
}
