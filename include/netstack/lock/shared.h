#ifndef NETSTACK_SHAREDLOCK_H
#define NETSTACK_SHAREDLOCK_H

#include <pthread.h>

/*
 * Shared Locks using pthread_rwlock
 */

enum shared_mode {
    SHARED_RD,
    SHARED_RW
};

#define shared_init(lock)      pthread_rwlock_init((lock), NULL)

#define shared_lock(lock, mode) \
    (mode) == SHARED_RD ? pthread_rwlock_rdlock(lock) : ( \
    (mode) == SHARED_RW ? pthread_rwlock_wrlock(lock) : -1)

#define shared_unlock(lock) pthread_rwlock_unlock(lock)

#endif //NETSTACK_SHAREDLOCK_H
