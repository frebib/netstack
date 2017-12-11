#include <stdio.h>
#include <stdlib.h>

#include <netstack/llist.h>

struct llist_elem *llist_prepend(struct llist_elem *list, void *data) {
    struct llist_elem *new = malloc(sizeof(struct llist_elem));
    if (!new) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    new->data = data;
    if (list) {
        new->prev = list->prev;
        new->next = list;
        if (list->prev)
            list->prev->next = new;
    } else {
        new->next = NULL;
        new->prev = NULL;
    }
    return new;
}

struct llist_elem *llist_append(struct llist_elem *list, void *data) {
    struct llist_elem *new = malloc(sizeof(struct llist_elem));
    if (!new) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    new->data = data;
    if (list) {
        new->next = list->next;
        new->prev = list;
        if (list->next)
            list->next->prev = new;
        list->next = new;
    } else {
        new->next = NULL;
        new->prev = NULL;
    }
    return new;
}
void llist_remove(struct llist_elem *list) {
    if (!list)
        return;
    if (list->prev)
        list->prev = list->next;
    if (list->next)
        list->next = list->prev;
    free(list);
}

void llist_clear(struct llist_elem *head) {
    if (!head)
        return;
    struct llist_elem *next;
    do {
        next = head->next;
        free(head);
    } while (next);
}
