#ifndef NETSTACK_CONTIMER_H
#define NETSTACK_CONTIMER_H

#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>

#include <netstack/col/llist.h>


/*
 * Continuous Timer provides the same functionality as a standard timer but
 * has a much lower overhead than multiple successive timers. contimer uses only
 * one thread for all timer events instead of one thread per timer/event.
 */


enum contimer_state {
    WAITING,
    SLEEPING,
    CALLING,
    CANCELLED
};

typedef uint32_t contimer_event_t;

struct contimer {
    pthread_t thread;
    pthread_cond_t wait;
    void (*callback)(void *);
    llist_t timeouts;
    contimer_event_t nextid;
    bool running;
};

typedef struct contimer contimer_t;

struct contimer_event {
    struct timespec wake;
    enum contimer_state state;
    void (*callback)(void *);
    contimer_event_t id;
};

/*!
 * Initialise a new timer instance
 * Starts the backing thread
 * Must be deallocated with contimer_stop()
 * @param t timer instance
 * @param callback callback function for each event
 * @return see pthread_create(3)
 */
int contimer_init(contimer_t *timer, void (*callback)(void *));

/*!
 * Enqueue a new event on the timer
 * Events are executed in order of addition so later events will trigger after
 * earlier events even if the timeout is before
 * @param t timer instance to queue the event on
 * @param abs absolute time to have elapsed when the event callback triggers
 * @param cb  an override callback function. if non-NULL, it will be called
 *            instead of the default set in the contimer_t
 * @param arg argument pointer to copy data from
 * @param len argument length to copy
 * @return a timer event that can be used to cancel the event
 */
contimer_event_t contimer_queue(contimer_t *timer, struct timespec *abs,
                                void (*cb)(void *), void *arg, size_t len);

/*!
 * Enqueues an event exactly the same as contimer_queue except takes a timespec
 * relative to the time that this function is called.
 * @param rel   Relative time from the current CLOCK_MONOTONIC time. Upon return
 *              this value is set to the absolute time the timeout started
 */
contimer_event_t contimer_queue_rel(contimer_t *t, struct timespec *rel,
                                    void (*cb)(void *), void *arg, size_t len);

/*!
 * Gets whether the event identified by id is a valid event that has not
 * expired or cancelled. If the return value is true, and a state pointer is
 * provided, additionally the state is passed back too.
 * @param timer timer that the event belongs to
 * @param id    id of the event in question
 * @param state pointer to a state storage
 * @return true if the event is alive, false otherwise
 */
bool contimer_isevent(contimer_t *timer, contimer_event_t *id,
                      enum contimer_state *state);

/*!
 * Cancels an enqueued timer event
 * Does nothing if the event is triggering or has already elapsed
 * @param id event to cancel
 * @return 0 on success, -EINVAL if timer is NULL, -ENOENT if id is not a valid
 *         event for timer or if the event has ended, -ETIME if the event has
 *         already timed-out/elapsed, -EALREADY if the event has been previously
 *         cancelled
 */
int contimer_cancel(contimer_t *timer, contimer_event_t id);

/*!
 * Stops the timer, cancels all events that have not elapsed yet and waits for
 * the backing thread to terminate
 * @return see pthread_join(3)
 */
int contimer_stop(contimer_t *timer);


#endif //NETSTACK_CONTIMER_H
