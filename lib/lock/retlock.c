#include <netstack/lock/retlock.h>

void retlock_init(retlock_t *lock) {
    pthread_mutex_init(&lock->lock, NULL);
    pthread_cond_init(&lock->wait, NULL);
    lock->val = 0;
}

int retlock_lock(retlock_t *lock) {
    return pthread_mutex_lock(&lock->lock);
}

int retlock_trylock(retlock_t *lock) {
    return pthread_mutex_trylock(&lock->lock);
}

int retlock_unlock(retlock_t *lock) {
    return pthread_mutex_unlock(&lock->lock);
}

int retlock_wait(retlock_t *lock, int *value) {
    retlock_lock(lock);
    int ret;
    if ((ret = pthread_cond_wait(&lock->wait, &lock->lock) != 0))
        return ret;
    *value = lock->val;
    return retlock_unlock(lock);
}

int retlock_timedwait(retlock_t *lock, struct timespec *t, int *value) {
    retlock_lock(lock);
    int ret = pthread_cond_timedwait(&lock->wait, &lock->lock, t);
    if (ret != 0)
        return -ret;
    *value = lock->val;
    retlock_unlock(lock);
    return ret;
}

int retlock_signal(retlock_t *lock, int value) {
    int ret;
    if ((ret = pthread_mutex_lock(&lock->lock)))
        return -ret;
    lock->val = value;
    if ((ret = pthread_cond_signal(&lock->wait)))
        return -ret;
    return retlock_unlock(lock);
}

int retlock_broadcast(retlock_t *lock, int value) {
    int ret;
    if ((ret = pthread_mutex_lock(&lock->lock)))
        return -ret;
    lock->val = value;
    if ((ret = pthread_cond_broadcast(&lock->wait)))
        return -ret;
    return retlock_unlock(lock);
}
