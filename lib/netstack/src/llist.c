#include <stdio.h>
#include <stdlib.h>

#include <netstack/llist.h>

void llist_clear(struct llist *list) {
    if (list == NULL)
        return;

    while (list->head)
        free(llist_pop(list));
    list->length = 0;
}

void llist_append(struct llist *list, void *data) {
    struct llist_elem *last = malloc(sizeof(struct llist_elem));
    last->data = data;
    last->next = NULL;
    last->prev = list->tail;
    if (list->tail)
        list->tail->next = last;
    if (!list->head)
        list->head = last;
    list->tail = last;
    list->length++;
}

void llist_push(struct llist *list, void *data) {
    struct llist_elem *first = malloc(sizeof(struct llist_elem));
    first->data = data;
    first->prev = NULL;
    first->next = list->head;
    if (list->head)
        list->head->prev = first;
    if (!list->tail)
        list->tail = first;
    list->head = first;
    list->length++;
}

void *llist_pop(struct llist *list) {
    if (!list->head)
        return NULL;

    struct llist_elem *toRemove = list->head;
    void *data = toRemove->data;
    list->head = toRemove->next;
    if (list->head)
        list->head->prev = NULL;
    else
        list->tail = NULL;

    list->length--;
    free(toRemove);
    return data;
}

void *llist_pop_last(struct llist *list) {
    if (!list->tail)
        return NULL;

    struct llist_elem *toRemove = list->head;
    void *data = toRemove->data;
    list->tail = list->tail->prev;
    if (list->tail)
        list->tail->next = NULL;
    else
        list->head = NULL;

    list->length--;
    free(toRemove);
    return data;
}

ssize_t llist_contains(struct llist *list, void *data) {
    if (list == NULL)
        return -1;
    if (data == NULL)
        return -1;

    ssize_t i = 0;
    for_each_llist(list) {
        if (llist_elem_data() == data)
            // Return index of found element
            return i;
        i++;
    }
    return -1;
}
