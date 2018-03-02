#ifndef NETSTACK_LLIST_H
#define NETSTACK_LLIST_H

#include <stdio.h>
#include <pthread.h>

#define LLIST_INITIALISER { \
        .lock = PTHREAD_MUTEX_INITIALIZER, \
        .head = NULL, \
        .tail = NULL, \
        .length = 0 \
    }

struct llist_elem {
    void *data;
    struct llist_elem *next, *prev;
};
typedef struct llist {
    pthread_mutex_t lock;
    struct llist_elem *head, *tail;
    size_t length;
} llist_t;

/*!
 * Iterate over each element in a loop.
 * Call llist_elem_data() to get the pointer to the element data
 * @param list list iterate over
 */
#define for_each_llist(list) \
    for (struct llist_elem *elem = (list)->head, \
        *next = (elem ? elem->next : NULL); elem != NULL; \
        elem = next, next = (elem ? elem->next : NULL))

#define llist_iter(list, fn) \
    for_each_llist(list) \
        fn(llist_elem_data())

/*!
 * For use in a for_each_llist(list) block.
 * Retrieves and casts the list entry data to the specified \a type
 */
#define llist_elem_data() ((elem)->data)

#define llist_head(list) (list)->head == NULL ? NULL : (list)->head->data

#define llist_tail(list) (list)->tail == NULL ? NULL : (list)->tail->data

/* Add queue compatibility */
#define queue_push llist_append
#define queue_pop  llist_pop

/*!
 * Remove every element from the list, emptying it.
 * Caution: This will not deallocate the element data,
 *          that must be done beforehand
 */
void llist_clear(llist_t *list);

/*!
 * Adds a new element to the end of the list
 */
void llist_append(llist_t *list, void *data);

/*!
 * Inserts a new element to the start of the list (prepend)
 * @param list list to prepend to
 * @param data data to prepend to the start of the list
 */
void llist_push(llist_t *list, void *data);

/*!
 * Fetch and remove the first element from the list
 * @return data from the first element of the list
 */
void *llist_pop(llist_t *list);

/*!
 * Fetch and remove the last element from the list
 * @return data from the last element of the list
 */
void *llist_pop_last(llist_t *list);

/*!
 * Inserts an element into an already-sorted list at the correct sorted location
 * @param list
 * @param data
 * @param cmp comparison function for determining list position
 */
void llist_insert_sorted(llist_t *list, void *data,
                         int (*cmp)(void *, void *));

/*!
 * Fetch the first element from the list, without removing it
 * @return data from the first element of the list
 */
void *llist_peek(llist_t *list);

/*!
 * Checks if a list contains an data element
 * Comparison is made by strict pointer checking
 * @return the index of the element if found, -1 otherwise
 */
ssize_t llist_contains(llist_t *list, void *data);

/*!
 * Removes a data element from the list if it exists.
 * Only removes the first instance of an element if it
 * resides in the list more than once.
 * Comparison is made by strict pointer checking.
 * @return 0 if the element was removed, -1 otherwise
 */
ssize_t llist_remove(llist_t *list, void *data);

/*!
 * Return the first element in list that matches the predicate function pred
 * @param list list to search through
 * @param pred predicate function to call for each element.
 *             the second argument will be the item from the list
 * @param arg first argument to pass to the predicate function
 * @return a pointer to the first data element that matches the predicate pred
 *         or NULL if there are no matches in list
 */
void *llist_first(llist_t *list, bool (*pred)(void *, void *), void *arg);


/*
 * Non-locking llist functions
 */
void llist_append_nolock(llist_t *list, void *data);
void llist_push_nolock(llist_t *list, void *data);
void *llist_pop_nolock(llist_t *list);
void *llist_peek_nolock(llist_t *list);
void *llist_pop_last_nolock(llist_t *list);
void llist_insert_sorted_nolock(llist_t *list, void *data,
                                int (*cmp)(void *, void *));
ssize_t llist_remove_nolock(llist_t *list, void *data);
void *llist_first_nolock(llist_t *list, bool (*pred)(void *, void *), void *arg);

#endif //NETSTACK_LLIST_H

