#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <signal.h>

#include <netstack/log.h>
#include <netstack/time/contimer.h>

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

    pthread_mutex_lock(&t->timeouts.lock);
    while (t->running) {
        int ret;
        struct contimer_event *event;

        event = llist_peek_nolock(&t->timeouts);

        // If there is no event in the queue, wait for one to be added
        if (event == NULL) {
            LOG(LVERB, "[CONTIMER] no timers left. Waiting for one");
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
            // Don't hold the lock whilst we sleep, it causes unwanted contention
            pthread_mutex_unlock(&t->timeouts.lock);

            // Sleep for the timeout then callback
            ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &event->wake, NULL);

            // Ensure after unlocking we check if any state has been changed
            // such as an event cancellation or a stopped t
            pthread_mutex_lock(&t->timeouts.lock);

            // The t has been stopped. Clean-up and exit
            if (event->state == CANCELLED || !t->running) {
                goto event_cleanup;
            }

            // We were woken by a signal. Go back to sleep
            if (ret == EINTR) {
                LOG(LVERB, "[CONTIMER] clock_nanosleep woken by a signal.");
                continue;
            }
            else if (ret != 0) {
                LOGSE(LERR, "clock_nanosleep", ret);
                goto event_cleanup;
            }
            // 0 is time elapsed
        } while (ret != 0);

        LOG(LTRCE, "[CONTIMER] timer elapsed. calling callback");

        contimeout_change_state(event, CALLING);

        // Now the t has elapsed, call the callback, cleanup, and loop again
        pthread_mutex_unlock(&t->timeouts.lock);
        t->callback(&event->arg);
        pthread_mutex_lock(&t->timeouts.lock);

    event_cleanup:
        llist_remove_nolock(&t->timeouts, event);

        LOGFN(LVERB, "free(%p)'ing contimer event %u", event, event->id);
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
    pthread_cond_init(&t->wait, NULL);
    return pthread_create(&t->thread, NULL, _contimer_run, t);
}

contimer_event_t contimer_queue(contimer_t *t, struct timespec *abs,
                                void *arg, size_t len) {

    pthread_mutex_lock(&t->timeouts.lock);

    struct contimer_event *event = malloc(sizeof(struct contimer_event) + len - 1);
    event->id = t->nextid++;
    event->wake.tv_sec = abs->tv_sec;
    event->wake.tv_nsec = abs->tv_nsec;
    event->state = WAITING;

    // Copy arbitrary sized argument
    if (arg != NULL && len > 0) {
        memcpy(&event->arg, arg, len);
    }

    llist_append_nolock(&t->timeouts, event);

    // Signal the timer that there is a new event if it is waiting for one
    pthread_cond_signal(&t->wait);
    pthread_mutex_unlock(&t->timeouts.lock);

    return event->id;
}

contimer_event_t contimer_queue_rel(contimer_t *t, struct timespec *rel,
                                    void *arg, size_t len) {
    
    // Obtain the current time
    struct timespec abs = {0};
    clock_gettime(CLOCK_MONOTONIC, &abs);
    
    // Offset by the relative time
    abs.tv_sec += rel->tv_sec;
    abs.tv_nsec += rel->tv_nsec;
    // Account for nanosecond overflow
    if (abs.tv_nsec >= 1000000000) {
        abs.tv_nsec -= 1000000000;
        abs.tv_sec++;
    }

    // Enqueue the event
    return contimer_queue(t, &abs, arg, len);
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
            pthread_kill(timer->thread, SIGCONT);
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
        LOGFN(LVERB, "[CONTIMER] free(%p)'ing event %u", event, event->id);
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

    pthread_mutex_unlock(&timer->timeouts.lock);

    // Wake clock_nanosleep if it is sleeping
    pthread_kill(timer->thread, SIGCONT);

    // Wait for the thread to terminate
    return -pthread_join(timer->thread, NULL);
}