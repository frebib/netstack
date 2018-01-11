#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <netstack/log.h>
#include <netstack/timer.h>

// Private timer signal handler function
static void netstack_timer_handler(int sig, siginfo_t *si, void *uc);

int timeout_set(timeout_t *t, void (*fn)(void *), void *arg,
                time_t sec, time_t nsec) {

    // Source: https://stackoverflow.com/questions/18847883/multiple-timers-in-c

    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = netstack_timer_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(TIMER_SIGNAL, &sa, NULL)) {
        LOG(LERR, "sigaction() returned: %s", strerror(errno));
        return -1;
    }

    *t = (timeout_t) {NULL, fn, arg, {sec, nsec}};

    struct sigevent te = {0};
    te.sigev_notify = SIGEV_SIGNAL;
    te.sigev_signo = TIMER_SIGNAL;
    te.sigev_value.sival_ptr = t;
    if (timer_create(CLOCK_REALTIME, &te, &t->timer)) {
        LOG(LERR, "timer_create() returned: %s", strerror(errno));
        free(t);
        return -1;
    }

    struct itimerspec timerspec = {0};
    timerspec.it_value.tv_sec = sec;
    timerspec.it_value.tv_nsec = nsec;
    if (timer_settime(t->timer, 0, &timerspec, NULL)) {
        LOG(LERR, "timer_settime() returned: %s", strerror(errno));
        timeout_cancel(t);
        return -1;
    }

    LOG(LDBUG, "Timer set for %lus, %luns", sec, nsec);

    return 0;
}

inline void timeout_cancel(timeout_t *t) {
    if (t->timer)
        timer_delete(t->timer);
    t->timer = NULL;
}

int timeout_restart(timeout_t *t, time_t sec, time_t nsec) {
    if (!t) {
        errno = EINVAL;
        return -1;
    }

    timeout_cancel(t);
    sec  = (sec  == -1 ? sec  : t->timeout.tv_sec);
    nsec = (nsec == -1 ? nsec : t->timeout.tv_nsec);
    return timeout_set(t, t->func, t->arg, sec, nsec);
}

void netstack_timer_handler(int sig, siginfo_t *si, void *uc) {
    LOG(LDBUG, "%s() caught signal: %s", __func__, strsignal(sig));

    if (sig == TIMER_SIGNAL) {
        timeout_t *t = si->si_value.sival_ptr;
        LOG(LDBUG, "Timer expired. Calling handler");

        // Call passed function with provided argument
        t->func(t->arg);

        // Clean up allocated memory
        timeout_cancel(t);
    }
}
