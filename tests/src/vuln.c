// Classic pwnable-style sample used by the test-suite.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *gets(char *);

struct note {
    char *data;
    int size;
};

struct note *notes[16];

void win(void) {
    system("/bin/sh");
}

int menu(void) {
    puts("1. add");
    puts("2. show");
    puts("3. delete");
    puts("4. exit");
    printf("> ");
    int c;
    if (scanf("%d", &c) != 1)
        exit(1);
    return c;
}

void add_note(void) {
    int idx = 0;
    while (idx < 16 && notes[idx])
        idx++;
    if (idx == 16) {
        puts("full");
        return;
    }
    int size;
    printf("size: ");
    scanf("%d", &size);
    notes[idx] = malloc(sizeof(struct note));
    notes[idx]->data = malloc(size);
    notes[idx]->size = size;
    printf("data: ");
    read(0, notes[idx]->data, size);
}

void show_note(int i) {
    if (i < 0 || i >= 16 || !notes[i])
        return;
    printf(notes[i]->data); // format string bug
    putchar('\n');
}

void del_note(int i) {
    free(notes[i]->data); // UAF
    free(notes[i]);
}

int checksum(const char *s) {
    int h = 0;
    for (int i = 0; s[i]; i++) {
        h = h * 31 + s[i];
        if (h > 100000)
            h ^= 0x1337;
    }
    return h;
}

int classify(int x) {
    switch (x) {
    case 0: return 10;
    case 1: return 22;
    case 2: return 37;
    case 3: return 41;
    case 4: return 59;
    case 5: return 63;
    default: return -1;
    }
}

void vuln(void) {
    char buf[64];
    puts("name?");
    gets(buf); // stack overflow
    printf("hello %s (%d)\n", buf, checksum(buf));
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1) {
        vuln();
        return classify(atoi(argv[1]));
    }
    for (;;) {
        int c = menu();
        if (c == 1)
            add_note();
        else if (c == 2)
            show_note(menu());
        else if (c == 3)
            del_note(menu());
        else
            break;
    }
    return 0;
}
