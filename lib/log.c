#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sysexits.h>

#ifdef _GNU_SOURCE
#include <pthread.h>
#endif

#include <netstack/log.h>
#include <errno.h>

struct log_config logconf = {
        .streams = LLIST_INITIALISER,
        .lvlstr  = {
                [LCRIT] = "CRITICAL",
                [LERR]  = "ERROR",
                [LWARN] = "WARN",
                [LNTCE] = "NOTICE",
                [LINFO] = "INFO",
                [LDBUG] = "DEBUG",
                [LTRCE] = "TRACE",
        }
};

void log_default(void) {
    struct log_stream *out = malloc(sizeof(struct log_stream));
    out->stream = stdout;
    out->min = LNULL;
    out->max = LWARN - 1;
    llist_append(&logconf.streams, out);
    struct log_stream *err = malloc(sizeof(struct log_stream));
    err->stream = stderr;
    err->min = LWARN;
    err->max = loglvl_max - 1;
    llist_append(&logconf.streams, err);
}


/*
 * Non-varadic functions definitions
 */
inline void LOG(loglvl_t level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    VLOG(level, fmt, args);
    va_end(args);
}

inline void LOGF(FILE *file, loglvl_t level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    VLOGF(file, level, fmt, args);
    va_end(args);
}

inline void TLOG(loglvl_t level, struct timespec *t, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    VTLOG(level, t, fmt, args);
    va_end(args);
}

inline void TLOGF(FILE *file, loglvl_t level, struct timespec *t,
                  const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    VTLOGF(file, level, t, fmt, args);
    va_end(args);
}

inline void LOGT(struct log_trans *trans, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    VLOGT(trans, fmt, args);
    va_end(args);
}


/*
 * Varadic function implementations
 */
inline void VLOG(loglvl_t level, const char *fmt, va_list args) {
    VTLOG(level, NULL, fmt, args);
}

inline void VLOGF(FILE *file, loglvl_t level, const char *fmt, va_list args) {
    VTLOGF(file, level, NULL, fmt, args);
}

void VTLOG(loglvl_t level, struct timespec *t, const char *fmt,
           va_list args) {
    for_each_llist(&logconf.streams) {
        struct log_stream *stream = llist_elem_data();
        if (level >= stream->min && level <= stream->max) {
            VTLOGF(stream->stream, level, t, fmt, args);
        }
    }
}

void VTLOGF(FILE *file, loglvl_t level, struct timespec *t, const char *fmt,
           va_list args) {
    va_list args2;
    va_copy(args2, args);

    // Calculate string length
    int prelen = 0;
    size_t maxlen = 128;
    char pre[maxlen];

    // Capture time now if one isn't specified
    struct timespec ts = {0};
    if (t == NULL) {
        timespec_get(&ts, TIME_UTC);
        t = &ts;
    }

    // Format and print time the same as tcpdump for comparison
    prelen += strftime(pre, maxlen, "%T", gmtime(&t->tv_sec));
    prelen += snprintf(pre + 8, 12, ".%09ld ", t->tv_nsec);

    // Append thread name to pre
#ifdef _GNU_SOURCE
    char name[32] = {0};
    pthread_getname_np(pthread_self(), name, 32);
    prelen += snprintf(pre + prelen, maxlen, "[%s] ", name);
#endif

    // Append log level to pre
    prelen += snprintf(pre + prelen, maxlen, "[%s] ", logconf.lvlstr[level]);

    // Produce formatted string
    int len = vsnprintf(NULL, 0, fmt, args) + 1;
    char str[len];
    vsnprintf(str, (size_t) len, fmt, args2);

    // Print to output file
    char *line, *tmp = str;
    // Print line-by-line using \n as delimiter
    while ((line = strtok_r(NULL, "\n", &tmp)) != NULL)
        fprintf(file, "%s%s\n", pre, line);
}

void VLOGT(struct log_trans *trans, const char *fmt, va_list args) {
    if (trans == NULL || fmt == NULL)
        return;

    va_list args2;
    va_copy(args2, args);

    // Calculate and format new string
    int len = vsnprintf(NULL, 0, fmt, args) + 1;
    // realloc buffer big enough
    size_t tstrlen = (trans->str ? strlen(trans->str) : 0);
    size_t minsize = tstrlen + len;
    if (trans->strsize < minsize) {
        // Find next size that accommodates entire string
        bool empty = (trans->strsize == 0);
        size_t newsize = empty ? LOG_TRANS_INIT_BUFFER : trans->strsize;
        do newsize *= 2;
        while (newsize <= minsize);

        if ((trans->str = realloc(trans->str, newsize)) == NULL) {
            LOGERR("realloc");
            exit(EX_OSERR);
        }
    }

    vsnprintf(trans->str + tstrlen, (size_t) len, fmt, args2);
}

void LOGT_COMMIT(struct log_trans *trans) {
    if (trans == NULL)
        return;

    // Pass NULL if the timespec is 0
    struct timespec *t = (trans->time.tv_sec == 0 &&
                            trans->time.tv_nsec == 0)
                             ? NULL : &trans->time;
    TLOG(trans->level, t, trans->str);
    LOGT_DISPOSE(trans);
}

void LOGT_DISPOSE(struct log_trans *trans) {
    if (trans != NULL && trans->str)
        free(trans->str);
}
