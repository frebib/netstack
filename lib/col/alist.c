#include <stdlib.h>
#include <errno.h>

#define NETSTACK_LOG_UNIT "ALIST"
#include <netstack/log.h>
#include <netstack/col/alist.h>

int _alist_init(void *lst, size_t type_sz, size_t init_sz) {
    if (lst == NULL || type_sz < 1 || init_sz < 1)
        return -EINVAL;

    // Implicitly cast to known type. If the user passed a
    // non-alist type, it's their funeral, not ours!
    alist_t *list = lst;

    // Allocate array storage
    if ((list->arr = malloc(type_sz * init_sz)) == NULL)
        return -ENOMEM;

    list->count = 0;
    list->type_sz = type_sz;
    list->len = init_sz;

    return 0;
}

int alist_expand(struct alist *list) {
    // Attempt to realloc twice the current allocated space
    void *inc;
    if ((inc = realloc(list->arr, (list->len * 2) * list->type_sz))) {
        return -ENOMEM;
    } else {
        // Success! Update the list
        list->len *= 2;
        list->arr = inc;
    }
    return 0;
}

void alist_free(void *lst) {
    alist_t *list = lst;
    if (list->arr != NULL)
        free(list->arr);
}

ssize_t alist_add(void *lst, void **newelem) {
    alist_t *list = lst;
    int ret;
    alist_lock(list);
    // If the list is full, expand it
    if (list->len == list->count) {
        if ((ret = alist_expand(list))) {
            alist_unlock(list);
            return ret;
        }
    }

    // Increment list count and get the elem at count
    *newelem = alist_elem(list, list->count++);
    alist_unlock(list);
    return (int) (list->count - 1);
}

