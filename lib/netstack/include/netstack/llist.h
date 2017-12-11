#ifndef NETSTACK_LLIST_H
#define NETSTACK_LLIST_H

struct llist_elem {
    void *data;
    struct llist_elem *next, *prev;
};

struct llist_elem *llist_prepend(struct llist_elem *list, void *data);

/* Appends a new element after the provided elem
 * returns pointer to new element */
struct llist_elem *llist_append(struct llist_elem *list, void *data);
void llist_remove(struct llist_elem *list);
void llist_clear(struct llist_elem *head);

#define for_each_llist(head) \
    for (struct llist_elem *elem = (head); elem != NULL; elem = elem->next)

#endif //NETSTACK_LLIST_H