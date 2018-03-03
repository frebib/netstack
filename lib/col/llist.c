#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define NETSTACK_LOG_UNIT "LLIST"
#include <netstack/log.h>
#include <netstack/col/llist.h>


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
    llist_append_nolock(list, data);
    pthread_mutex_unlock(&list->lock);
}

void llist_append_nolock(llist_t *list, void *data) {
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

void llist_push(llist_t *list, void *data) {
    pthread_mutex_lock(&list->lock);
    llist_push_nolock(list, data);
    pthread_mutex_unlock(&list->lock);
}

void llist_push_nolock(llist_t *list, void *data) {
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

void llist_insert_sorted(llist_t *list, void *data,
                         int (*cmp)(void *, void *)) {
    pthread_mutex_lock(&list->lock);
    llist_insert_sorted_nolock(list, data, cmp);
    pthread_mutex_unlock(&list->lock);
}

void llist_insert_sorted_nolock(llist_t *list, void *data,
                                int (*cmp)(void *, void *)) {

    // Find the sorted location within the list and insert it
    struct llist_elem *elem;
    for (elem = list->head; elem != NULL; elem = elem->next) {
        // If elem->data > data
        if (cmp(data, elem->data) > 0) {
            // Insert the element here!
            break;
        }
    }

    // If no next element, we're at the end of list so append
    if (elem == NULL) {
        llist_append_nolock(list, data);
        return;
    }

    // Somewhere in the middle of the list. Insert before elem
    struct llist_elem *insert = malloc(sizeof(struct llist_elem));
    insert->data = data;
    insert->next = elem;
    insert->prev = elem->prev;
    elem->prev = insert;

    // Increase list length
    list->length++;

    // If insert at list[0], set head pointer
    if (insert->prev == NULL)
        list->head = insert;
    // Otherwise set previous next pointer
    else
        insert->prev->next = insert;
}

void *llist_peek(llist_t *list) {
    pthread_mutex_lock(&list->lock);
    void *data = llist_peek_nolock(list);
    pthread_mutex_unlock(&list->lock);
    return data;
}

void *llist_peek_nolock(llist_t *list) {
    return (list != NULL && list->head != NULL)
                ? list->head->data
                : NULL;
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

ssize_t llist_remove_nolock(llist_t *list, void *data) {
    if (data == NULL)
        return -EINVAL;

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
        return 0;
    }
    return -ENODATA;
}

ssize_t llist_remove(llist_t *list, void *data) {
    if (list == NULL)
        return -EINVAL;

    pthread_mutex_lock(&list->lock);
    ssize_t ret = llist_remove_nolock(list, data);
    pthread_mutex_unlock(&list->lock);
    return ret;
}

void *llist_first(llist_t *list, bool (*pred)(void *, void *), void *arg) {

    pthread_mutex_lock(&list->lock);
    void *ret = llist_first_nolock(list, pred, arg);
    pthread_mutex_unlock(&list->lock);
    return ret;
}

void *llist_first_nolock(llist_t *list, bool (*pred)(void *, void *), void *arg) {

    for_each_llist(list) {
        void *data = llist_elem_data();
        if (pred(arg, data)) {
            return data;
        }
    }
    return NULL;
}
