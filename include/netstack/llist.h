#ifndef NETSTACK_LLIST_H
#define NETSTACK_LLIST_H

#include <stdio.h>

#define LLIST_INITIALISER { .head = NULL, .tail = NULL, .length = 0 }

struct llist_elem {
    void *data;
    struct llist_elem *next, *prev;
};
struct llist {
    struct llist_elem *head, *tail;
    size_t length;
};

/*!
 * Iterate over each element in a loop.
 * Call llist_elem_data() to get the pointer to the element data
 * @param list list iterate over
 */
#define for_each_llist(list) \
    for (struct llist_elem *elem = (list)->head; \
        elem != NULL; \
        elem = elem->next)

#define llist_iter(list, fn) \
    for_each_llist(list) \
        fn(llist_elem_data())

/*!
 * For use in a for_each_llist(list) block.
 * Retrieves and casts the list entry data to the specified \a type
 */
#define llist_elem_data() ((elem)->data)


/* Add queue compatibility */
#define queue_push llist_append
#define queue_pop  llist_pop

/*!
 * Remove every element from the list, emptying it.
 * Caution: This will not deallocate the element data,
 *          that must be done beforehand
 */
void llist_clear(struct llist *list);

/*!
 * Adds a new element to the end of the list
 */
void llist_append(struct llist *list, void *data);

/*!
 * Inserts a new element to the start of the list (prepend)
 * @param list list to prepend to
 * @param data data to prepend to the start of the list
 */
void llist_push(struct llist *list, void *data);

/*!
 * Fetch and remove the first element from the list
 * @return data from the first element of the list
 */
void *llist_pop(struct llist *list);

/*!
 * Fetch and remove the last element from the list
 * @return data from the last element of the list
 */
void *llist_pop_last(struct llist *list);

/*!
 * Checks if a list contains an data element
 * Comparison is made by strict pointer checking
 * @return the index of the element if found, -1 otherwise
 */
ssize_t llist_contains(struct llist *list, void *data);


#endif //NETSTACK_LLIST_H

