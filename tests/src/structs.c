// Struct layouts for the struct-recovery tests: fields of several widths, pointers to
// structs in a global array, nested access through a struct pointer field.
#include <stdlib.h>
#include <string.h>

struct item {
    char *name;
    int count;
    short kind;
    long long total;
};

struct node {
    int key;
    struct item *it;
    struct node *next;
};

struct item *pool[4];

int item_score(struct item *it) {
    return it->count * 3 + it->kind - (int)(it->total >> 4);
}

void item_add(struct item *it, int k) {
    it->count += k;
    it->total += (long long)k * it->kind;
}

int name_len(struct item *it) {
    return it->name ? (int)strlen(it->name) + it->kind : -1;
}

int pool_total(void) {
    int s = 0;
    for (int i = 0; i < 4; i++)
        if (pool[i])
            s += pool[i]->count + pool[i]->kind;
    return s;
}

int pool_first(void) {
    return pool[0] ? item_score(pool[0]) : 0;
}

int chain_sum(struct node *n) {
    int s = 0;
    for (; n; n = n->next)
        s += n->key * 2 + (n->it ? n->it->count : 0);
    return s;
}

int main(int argc, char **argv) {
    struct item a = {argv[0], argc, 2, 1000};
    pool[0] = &a;
    item_add(&a, 3);
    return item_score(&a) + pool_total() + name_len(&a) + pool_first();
}
