#ifndef NETSTACK_QUEUE_H
#define NETSTACK_QUEUE_H

#include <netstack/llist.h>

struct queue {
    struct llist_elem *head, *tail;
};

void queue_init(struct queue *q);
void queue_push(struct queue *q, void *data);
void *queue_peek(struct queue *q);
void *queue_pop(struct queue *q);

#define queue_list(q) (q)->head

#endif //NETSTACK_QUEUE_H
