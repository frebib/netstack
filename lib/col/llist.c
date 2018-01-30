#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <netstack/col/llist.h>

// Private
void *llist_pop_nolock(llist_t *list);
void *llist_pop_last_nolock(llist_t *list);


void llist_clear(llist_t *list) {
    if (list == NULL)
        return;

    pthread_mutex_lock(&list->lock);

    struct llist_elem *tmp  = list->head,
                      *next = NULL;
    while (tmp) {
        next = tmp->next;
        free(tmp);
        tmp = next;
    }
    list->length = 0;

    pthread_mutex_unlock(&list->lock);
}

void llist_append(llist_t *list, void *data) {
    pthread_mutex_lock(&list->lock);

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

    pthread_mutex_unlock(&list->lock);
}

void llist_push(llist_t *list, void *data) {
    pthread_mutex_lock(&list->lock);

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

    pthread_mutex_unlock(&list->lock);
}

void *llist_pop_nolock(llist_t *list) {
    if (!list->head)
        return NULL;

    struct llist_elem *remove = list->head;
    void *data = remove->data;
    list->head = list->head->next;
    if (list->head)
        list->head->prev = NULL;
    else
        list->tail = NULL;

    list->length--;
    free(remove);

    return data;
}

void *llist_pop(llist_t *list) {
    pthread_mutex_lock(&list->lock);
    void* ret = llist_pop_nolock(list);
    pthread_mutex_unlock(&list->lock);
    return ret;
}

void *llist_pop_last_nolock(llist_t *list) {
    if (!list->tail)
        return NULL;

    struct llist_elem *remove = list->tail;
    void *data = remove->data;
    list->tail = list->tail->prev;
    if (list->tail)
        list->tail->next = NULL;
    else
        list->head = NULL;

    list->length--;
    free(remove);

    return data;
}

void *llist_pop_last(llist_t *list) {
    pthread_mutex_lock(&list->lock);
    void* ret = llist_pop_last_nolock(list);
    pthread_mutex_unlock(&list->lock);
    return ret;
}

void *llist_peek(llist_t *list) {
    if (!list)
        return NULL;
    void *data = NULL;
    pthread_mutex_lock(&list->lock);
    if (list->head)
        data = list->head->data;
    pthread_mutex_unlock(&list->lock);
    return data;
}

ssize_t llist_contains(llist_t *list, void *data) {
    if (list == NULL || data == NULL)
        return -EINVAL;

    pthread_mutex_lock(&list->lock);

    ssize_t i = 0;
    for_each_llist(list) {
        if (llist_elem_data() == data) {
            // Return index of found element
            pthread_mutex_unlock(&list->lock);
            return i;
        }
        i++;
    }
    pthread_mutex_unlock(&list->lock);
    return -ENODATA;
}

ssize_t llist_remove(llist_t *list, void *data) {
    if (list == NULL || data == NULL)
        return -EINVAL;

    pthread_mutex_lock(&list->lock);

    for_each_llist(list) {
        if (llist_elem_data() != data)
            continue;

        // If no prev, must be head
        if (!elem->prev)
            llist_pop_nolock(list);
        // If no next, must be tail
        else if (!elem->next)
            llist_pop_last_nolock(list);
        else {
            // Has a next and prev element
            elem->prev->next = elem->next;
            elem->next->prev = elem->prev;
            list->length--;
            free(elem);
        }

        pthread_mutex_unlock(&list->lock);
        return 0;
    }

    pthread_mutex_unlock(&list->lock);
    return -ENODATA;
}
