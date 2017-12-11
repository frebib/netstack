#include <stdio.h>
#include <stdlib.h>

#include <netstack/queue.h>

void queue_init(struct queue *q) {
    q->head = NULL;
    q->tail = NULL;
}
void queue_push(struct queue *q, void *data) {
    if (!q) return;

    struct llist_elem *tail = llist_append(q->tail, data);
    q->tail = tail;

    if (q->head == NULL)
        q->head = q->tail;
}
void *queue_peek(struct queue *q) {
    if (!q) return NULL;
    if (!q->head) return NULL;

    return q->head->data;
}
void *queue_pop(struct queue *q) {
    if (!q) return NULL;
    if (!q->head) return NULL;

    void *data = q->head->data;
    if (q->head == q->tail) {
        free(q->head);
        q->head = NULL;
        q->tail = NULL;
    } else {
        struct llist_elem *second = q->head->next;
        free(q->head);
        q->head = second;
    }
    return data;
}

