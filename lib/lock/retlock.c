#include <string.h>

#include <netstack/log.h>
#include <netstack/lock/retlock.h>

void retlock_init(retlock_t *lock) {
    pthread_mutex_init(&lock->lock, NULL);
    pthread_cond_init(&lock->wait, NULL);
    lock->val = 0;
}

int retlock_lock(retlock_t *lock) {
    return -pthread_mutex_lock(&lock->lock);
}

int retlock_trylock(retlock_t *lock) {
    return -pthread_mutex_trylock(&lock->lock);
}

int retlock_unlock(retlock_t *lock) {
    return -pthread_mutex_unlock(&lock->lock);
}

int retlock_wait(retlock_t *lock, int *value) {
    int ret;
    if ((ret = retlock_lock(lock)))
        return ret;
    return retlock_wait_nolock(lock, value);
}

int retlock_wait_nolock(retlock_t *lock, int *value) {
    int ret;
    if ((ret = pthread_cond_wait(&lock->wait, &lock->lock) != 0))
        return -ret;
    if (value != NULL)
        *value = lock->val;
    return retlock_unlock(lock);
}

int retlock_timedwait(retlock_t *lock, struct timespec *t, int *value) {
    int ret;
    if ((ret = retlock_lock(lock)))
        return ret;
    return retlock_timedwait_nolock(lock, t, value);
}

int retlock_timedwait_nolock(retlock_t *lock, struct timespec *t, int *value) {
    int ret = pthread_cond_reltimedwait(&lock->wait, &lock->lock, t);
    if (ret != 0) {
        if (ret != ETIMEDOUT)
            LOGSE(LERR, "pthread_cond_timedwait", ret);
        retlock_unlock(lock);
        return ret;
    }
    if (value != NULL)
        *value = lock->val;
    return retlock_unlock(lock);
}

int retlock_signal(retlock_t *lock, int value) {
    int ret;
    if ((ret = retlock_lock(lock)))
        return ret;
    return retlock_signal_nolock(lock, value);
}

int retlock_signal_nolock(retlock_t *lock, int value) {
    int ret;
    lock->val = value;
    if ((ret = pthread_cond_signal(&lock->wait)))
        return -ret;
    return retlock_unlock(lock);
}

int retlock_broadcast(retlock_t *lock, int value) {
    int ret;
    if ((ret = retlock_lock(lock)))
        return ret;
    return retlock_broadcast_nolock(lock, value);
}

int retlock_broadcast_nolock(retlock_t *lock, int value) {
    int ret;
    lock->val = value;
    if ((ret = pthread_cond_broadcast(&lock->wait)))
        return -ret;
    return retlock_unlock(lock);
}

int pthread_cond_reltimedwait(pthread_cond_t *__restrict cond,
                              pthread_mutex_t *__restrict mutex,
                              const struct timespec *__restrict reltime) {

    // Add adsolute time onto the relative timeout
    struct timespec abs;
    clock_gettime(CLOCK_REALTIME, &abs);
    abs.tv_sec += reltime->tv_sec;
    abs.tv_nsec += reltime->tv_nsec;
    // Prevent nanoseconds being >= 1 billion
    if (abs.tv_nsec >= 1000000000) {
        abs.tv_nsec -= 1000000000;
        abs.tv_sec++;
    }

    return pthread_cond_timedwait(cond, mutex, &abs);
}
