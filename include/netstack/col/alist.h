#ifndef NETSTACK_ALIST_H
#define NETSTACK_ALIST_H

/*
 * ArrayList implementation
 */

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#define _ARRAYLIST_COMMON \
        /* Allocated length of the array */ \
        size_t len; \
        /* Amount of elements in the list */ \
        size_t count; \
        /* Size of one array element */ \
        size_t type_sz; \
        /* List access lock */ \
        pthread_mutex_t lock

typedef struct alist {
    _ARRAYLIST_COMMON;
    void *arr;
} alist_t;

/*!
 *  Use this macro to define a new arraylist type:
 *
 *  ARRAYLIST_DEFINE(mylist, struct { int a; void *b; });
 *  ARRAYLIST_DEFINE(mylist, struct timespec);
 *
 *  and refer to it as mylist_t
 *
 *  @param name name to use for arraylist type structure
 *  @param type type of element in the arraylist
 */
#define ARRAYLIST_DEFINE(name, type) \
    typedef struct name { \
        _ARRAYLIST_COMMON; \
        /* Pointer to the array */ \
        type *arr; \
    } name##_t

#define alist_lock(list)   pthread_mutex_lock(&(list)->lock)
#define alist_unlock(list) pthread_mutex_unlock(&(list)->lock)

#define alist_elem(list, n) ((list)->arr + ((list)->type_sz + n))

#define alist_init(list, size) _alist_init((list), sizeof(*(list)->arr), (size))

/*!
 *
 * @param list
 * @param type_sz
 * @param init_sz
 * @return
 */
int _alist_init(void *list, size_t type_sz, size_t init_sz);

/*!
 * Doubles the size of an arraylist. Does NOT lock the list- this must be
 * done by the user (although this function should never really be used)
 * @return 0 on success, -1 otherwise (if realloc(3) fails)
 */
int alist_expand(struct alist *list);

/*!
 * Deallocates arraylist memory
 */
void alist_free(void *lst);

/*!
 * Gets the pointer to a new element in the list. Expands list if more space
 * is required for the new element
 * This function makes no guarantees about the memory pointed to by newelem.
 * As with malloc(3), the memory is NOT initialised.
 * @param lst list to add element to
 * @param newelem pointer to set to new element pointer
 * @return 0 on success, -1 otherwise (if realloc(3) fails)
 */
int alist_add(void *lst, void **newelem);

#endif //NETSTACK_ALIST_H
