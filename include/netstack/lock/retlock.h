#ifndef NETSTACK_RETLOCK_H
#define NETSTACK_RETLOCK_H

#include <errno.h>
#include <pthread.h>

#define RETLOCK_INITIALISER { \
        .wait = PTHREAD_COND_INITIALIZER, \
        .lock = PTHREAD_MUTEX_INITIALIZER, \
        .val  = 0 \
    }

typedef struct retlock {
    pthread_cond_t wait;
    pthread_mutex_t lock;
    int val;
} retlock_t;


/*!
 * Initialises a new retlock structure
 */
void retlock_init(retlock_t *lock);

/*!
 * Locks the retlock
 * @return see pthread_mutex_lock(3P)
 */
int retlock_lock(retlock_t *lock);

/*!
 * Tries to lock the retlock, otherwise returns if it is already held
 * @return see pthread_mutex_trylock(3P)
 */
int retlock_trylock(retlock_t *lock);

/*!
 * Unlocks the retlock
 * @return see pthread_mutex_unlock(3P)
 */
int retlock_unlock(retlock_t *lock);

/*!
 * Waits for the lock condition and obtains the value but
 * does NOT lock or unlock the mutex
 * @param value pointer to write the returned value when the lock releases
 * @return see pthread_cond_wait(3P)
 */
int retlock_wait_bare(retlock_t *lock, int *value);

/*!
 * Waits for the lock to be signalled from another thread
 * @param value pointer to write the returned value when the lock releases
 * @return see pthread_cond_wait(3P)
 */
int retlock_wait(retlock_t *lock, int *value);

/*!
 * Waits for the lock to be signalled from another thread
 * Note: Does not lock the mutex before waiting. It is required for the user
 * to call retlock_lock before calling this function.
 * @param value pointer to write the returned value when the lock releases
 * @return see pthread_cond_wait(3P)
 */
int retlock_wait_nolock(retlock_t *lock, int *value);

/*!
 * Waits for the lock to be signalled from another thread
 * If no signal is caught within the timeout t, it returns ETIMEDOUT
 * @param value pointer to write the returned value when the lock releases
 * @return see pthread_cond_timedwait(3P)
 */
int retlock_timedwait(retlock_t *lock, struct timespec *t, int *value);

/*!
 * Waits for the lock to be signalled from another thread
 * If no signal is caught within the timeout t, it returns ETIMEDOUT
 * Note: Does not lock the mutex before waiting. It is required for the user
 * to call retlock_lock before calling this function.
 * @param value pointer to write the returned value when the lock releases
 * @return see pthread_cond_timedwait(3P)
 */
int retlock_timedwait_nolock(retlock_t *lock, struct timespec *t, int *value);

/*!
 * Signals one waiting thread with a value
 * Always locks and unlocks the lock before and after signalling the condition
 * @param value return value to send to waiting thread
 * @return see pthread_cond_signal(3P)
 */
int retlock_signal(retlock_t *lock, int value);

/*!
 * Signals one waiting thread with a value
 * Unlocks the mutex after signalling the condition
 * Note: Does not lock the mutex before waiting. It is required for the user
 * to call retlock_lock before calling this function.
 * @param value return value to send to waiting thread
 * @return see pthread_cond_signal(3P)
 */
int retlock_signal_nolock(retlock_t *lock, int value);

/*!
 * Broadcasts to all waiting threads with a value
 * Always locks and unlocks the lock before and after signalling the condition
 * @param value return value to send to waiting threads
 * @return see pthread_mutex_broadcast(3P)
 */
int retlock_broadcast(retlock_t *lock, int value);

/*!
 * Broadcasts to all waiting threads with a value
 * Unlocks the mutex after signalling the condition
 * Note: Does not lock the mutex before waiting. It is required for the user
 * to call retlock_lock before calling this function.
 * @param value return value to send to waiting thread
 * @return see pthread_cond_signal(3P)
 */
int retlock_broadcast_nolock(retlock_t *lock, int value);

/*!
 * Broadcasts to all waiting threads with a value
 * Note: Does not lock the mutex before waiting or after signalling!
 * It is required for the user to call retlock_lock before
 * and retlock_unlock after calling this function.
 * @param value return value to send to waiting thread
 * @return see pthread_cond_signal(3P)
 */
int retlock_broadcast_bare(retlock_t *lock, int value);



int pthread_cond_reltimedwait(pthread_cond_t *__restrict cond,
                              pthread_mutex_t *__restrict mutex,
                              const struct timespec *__restrict reltime);

#endif //NETSTACK_RETLOCK_H
