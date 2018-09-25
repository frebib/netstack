#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <signal.h>

#define NETSTACK_LOG_UNIT "CONTMR"
#include <netstack/log.h>
#include <netstack/time/contimer.h>
#include <netstack/time/util.h>

#define contimeout_change_state(event, newstate) \
    do { \
        if ((event)->state == CANCELLED) { \
            goto event_cleanup; \
        } else { \
            (event)->state = (newstate); \
        } \
    } while (0)

static bool contimer_event_id_pred(void *a, void *b) {
    int userid = *((int *) a);
    struct contimer_event *event = b;
    return (userid == event->id);
}

static void *_contimer_run(void *arg) {
    contimer_t *t = arg;

#ifdef _GNU_SOURCE
    char thread_name[64];
    pthread_getname_np(pthread_self(), thread_name, 64);
    strncat(thread_name, "/timer", 63);
    pthread_setname_np(pthread_self(), thread_name);
#endif

    pthread_mutex_lock(&t->timeouts.lock);
    while (t->running) {
        int ret;
        struct contimer_event *event;

        event = llist_peek_nolock(&t->timeouts);

        // If there is no event in the queue, wait for one to be added
        if (event == NULL) {
            LOG(LVERB, "no timers left. Waiting for one");
            ret = pthread_cond_wait(&t->wait, &t->timeouts.lock);
            if (ret != 0) {
                LOGSE(LERR, "pthread_cond_wait", ret);
                goto exit;
            }
            // Loop back around and try to get a timeout
            continue;
        }

        contimeout_change_state(event, SLEEPING);

        do {
            // Sleep for the timeout then callback
            ret = pthread_cond_timedwait(&t->wait, &t->timeouts.lock, &event->wake);

            // The t has been stopped. Clean-up and exit
            if (!t->running) {
                LOG(LVERB, "timer stopped, cleaning up");
                goto event_cleanup;
            } else if (event->state == CANCELLED) {
                LOG(LVERB, "event cancelled, cleaning up");
                goto event_cleanup;
            }

            // We were woken by a signal. Go back to sleep
            if (ret == EINTR) {
                LOG(LVERB, "pthread_cond_timedwait woken by a signal.");
                continue;
            }
            else if (ret != ETIMEDOUT) {
                LOGSE(LERR, "pthread_cond_timedwait", ret);
                goto event_cleanup;
            }
        // when timedout we are done sleeping
        } while (ret != ETIMEDOUT);

        LOG(LTRCE, "timer elapsed. calling callback");

        contimeout_change_state(event, CALLING);

        // If the event has an override callback, use that instead
        void (*cb)(void *) = (event->callback != NULL)
                                ? event->callback
                                : t->callback;

        // Now the t has elapsed, call the callback, cleanup, and loop again
        pthread_mutex_unlock(&t->timeouts.lock);
        cb(event + 1);
        pthread_mutex_lock(&t->timeouts.lock);

    event_cleanup:
        llist_remove_nolock(&t->timeouts, event);

        LOG(LVERB, "free(%p)'ing contimer event %u", event, event->id);
        free(event);
    }

exit:
    pthread_mutex_unlock(&t->timeouts.lock);
    return NULL;
}

int contimer_init(contimer_t *t, void (*callback)(void *)) {

    t->timeouts = (llist_t) LLIST_INITIALISER;
    t->nextid = 0;
    t->running = true;
    t->callback = callback;

    // Initialise the pthread_cond var with a MONOTONIC clock
    // Ideally we would use MONOTONIC_RAW but that is Linux-only
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&t->wait, &attr);

    return pthread_create(&t->thread, NULL, _contimer_run, t);
}

contimer_event_t contimer_queue(contimer_t *t, struct timespec *abs,
                                void (*cb)(void *), void *arg, size_t len) {

    pthread_mutex_lock(&t->timeouts.lock);

    struct contimer_event *event = malloc(sizeof(struct contimer_event) + len);
    event->id = t->nextid++;
    event->wake.tv_sec = abs->tv_sec;
    event->wake.tv_nsec = abs->tv_nsec;
    event->callback = cb;
    event->state = WAITING;

    // Copy arbitrary sized argument
    if (arg != NULL && len > 0) {
        memcpy(event + 1, arg, len);
    }

    LOG(LTRCE, "queuing event %d", event->id);
    llist_append_nolock(&t->timeouts, event);

    // Signal the timer that there is a new event if it is waiting for one
    pthread_cond_signal(&t->wait);
    pthread_mutex_unlock(&t->timeouts.lock);

    return event->id;
}

contimer_event_t contimer_queue_rel(contimer_t *t, struct timespec *rel,
                                    void (*cb)(void *), void *arg, size_t len) {
    
    // Obtain the current time
    struct timespec now, abs = {0};
    clock_gettime(CLOCK_MONOTONIC, &abs);
    
    // Offset by the relative time
    now = abs;
    timespecadd(&abs, rel);

    // Return the absolute time that the timer was started
    *rel = now;

    // Enqueue the event
    return contimer_queue(t, &abs, cb, arg, len);
}

bool contimer_isevent(contimer_t *timer, contimer_event_t *id,
                      enum contimer_state *state) {
    if (timer == NULL)
        return -EINVAL;

    pthread_mutex_lock(&timer->timeouts.lock);

    struct contimer_event *event;
    bool (*pred)(void *, void *) = contimer_event_id_pred;

    if ((event = llist_first_nolock(&timer->timeouts, pred, &id)) == NULL) {
        pthread_mutex_unlock(&timer->timeouts.lock);
        return false;
    }

    if (state != NULL)
        *state = event->state;

    pthread_mutex_unlock(&timer->timeouts.lock);
    return true;
}

int contimer_cancel(contimer_t *timer, contimer_event_t id) {
    if (timer == NULL)
        return -EINVAL;

    pthread_mutex_lock(&timer->timeouts.lock);

    // Ensure the event hasn't been freed before accessing it
    // This prevents use-after-free memory errors
    struct contimer_event *event;
    bool (*pred)(void *, void *) = contimer_event_id_pred;
    if ((event = llist_first_nolock(&timer->timeouts, pred, &id)) == NULL) {
        pthread_mutex_unlock(&timer->timeouts.lock);
        return -ENOENT;
    }

    llist_remove_nolock(&timer->timeouts, event);

    int ret = 0;
    bool should_free = false;
    switch (event->state) {
        case WAITING:
            should_free = true;
        case SLEEPING:
            event->state = CANCELLED;
            pthread_cond_signal(&timer->wait);
            ret = 0;
            break;
        case CALLING:
            ret = -ETIME;
            break;
        case CANCELLED:
            ret = -EALREADY;
            break;
    }

    // Only free the event when it is still in the WAITING state
    // Events in any other state will be free'd by the timer
    if (should_free) {
        LOG(LVERB, "free(%p)'ing event %u", event, event->id);
        free(event);
    }

    pthread_mutex_unlock(&timer->timeouts.lock);

    return ret;
}

int contimer_stop(contimer_t *timer) {
    if (timer == NULL)
        return -EINVAL;

    pthread_mutex_lock(&timer->timeouts.lock);

    timer->running = false;

    // Cancel or free all events
    struct contimer_event *event;
    while ((event = llist_pop_nolock(&timer->timeouts)) != NULL) {
        if (event->state == WAITING) {
            free(event);
        } else {
            // Any events that are cancelled will be free'd by the timer
            event->state = CANCELLED;
        }
    }

    // Wake the condition variable, if it is sleeping
    pthread_cond_signal(&timer->wait);
    pthread_mutex_unlock(&timer->timeouts.lock);

    // Wait for the thread to terminate
    return -pthread_join(timer->thread, NULL);
}