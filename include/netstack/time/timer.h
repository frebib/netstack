#ifndef NETSTACK_TIMER_H
#define NETSTACK_TIMER_H

#include <time.h>
#include <signal.h>
#include <pthread.h>

#define TIMER_SIGNAL    SIGUSR1

/*!
 * Represents the state of a timer and it's callback function
 */
typedef struct timer_data {
    timer_t timer;
    void (*func)(void *);
    void *arg;
    struct timespec timeout;
} timeout_t;


/*!
 * Creates and immediately starts a timeout with callback
 * @param t     timeout structure for storage. used for cancellation/restarting
 * @param fn    callback function
 * @param arg   argument to pass to callback function
 * @param sec   seconds until timeout
 * @param nsec  nanoseconds until timeout
 * @return 0 on success, -1 on error
 */
int timeout_set(timeout_t *t, void (*fn)(void *), void *arg,
                time_t sec, time_t nsec);

/*!
 * Stops the timeout if it has not completed
 * free()'s allocated t->timer if it was started
 * @param t
 */
void timeout_clear(timeout_t *t);

/*!
 * Clears and resets a timer
 * @param t     timeout_t to restart
 * @param sec   seconds until timeout (specify -1 to use original sec)
 * @param nsec  nano-seconds until timeout (specify -1 to use original nsec)
 * @return see timeout_set()
 *         EINVAL if t is NULL
 */
int timeout_restart(timeout_t *t, time_t sec, time_t nsec);

#endif //NETSTACK_TIMER_H
