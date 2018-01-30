#ifndef NETSTACK_LOG_H
#define NETSTACK_LOG_H

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

#include <netstack/col/llist.h>

#define LOG_TRANS_INIT_BUFFER   64      /* Initial log_trans buffer size */

/*
 * Global logging configuration
 */
extern struct log_config logconf;

typedef uint8_t loglvl_t;

/* 2^n where n is size of loglvl_t, times 8 bits per byte */
#define loglvl_max (1 << (sizeof(loglvl_t) * 8)) /* Max amount of log levels */

struct log_config {
    llist_t streams;            /* Standard logging output */
    char *lvlstr[loglvl_max];   /* String representations of log levels */
    pthread_mutex_t lock;
};

struct log_stream {
    FILE *stream;       /* Stream to write log entries to */
    loglvl_t min;       /* Minimum log level for stream (inclusive) */
    loglvl_t max;       /* Maximum log level for stream (inclusive) */
};

struct log_trans {
    loglvl_t level;
    struct timespec time;   /* Time to print before log entry. Defaults to
                               null in which case commit time will be used */
    char *str;          /* Transaction string buffer */
    size_t strsize;     /* Allocated size of str*/
};

struct pkt_log {
    struct log_trans t; /* Log transaction to write to */
    llist_t filter;     /* List of options, similar to those in tcpdump */
};

/*
 * Default log levels
 */
#define LCRIT 0xF0          /* Critical errors are usually terminal */
#define LERR  0xC0
#define LWARN 0xA0
#define LNTCE 0x80
#define LINFO 0x60
#define LDBUG 0x40
#define LVERB 0x20
#define LTRCE 0x10
#define LNULL 0x00


/*!
 * Initialise log_config with stdout and stderr default log streams
 */
void log_default(struct log_config *conf);

/*!
 * Generate log entry
 */
void LOG(loglvl_t level, const char *fmt, ...)
        __attribute__((__format__ (__printf__, 2, 3)));

void VLOG(loglvl_t level, const char *fmt, va_list args)
        __attribute__((__format__ (__printf__, 2, 0)));

void TLOG(loglvl_t level, struct timespec *t, const char *fmt, ...)
        __attribute__((__format__ (__printf__, 3, 4)));

void VTLOG(loglvl_t level, struct timespec *t, const char *fmt, va_list args)
        __attribute__((__format__ (__printf__, 3, 0)));

/*!
 * Equivalent of perror(3)
 * Calls LOGFN() to add file, line and function to log entry
 */
#define LOGERR(fmt, ...) \
    LOGFN(LERR,  fmt ": %s", ##__VA_ARGS__, strerror(errno))

/*!
 * Performs the same action as LOGERR() but takes the log level as a
 * parameter instead of defaulting to LERR
 */
#define LOGE(lvl, fmt, ...) \
    LOGFN((lvl), fmt ": %s", ##__VA_ARGS__, strerror(errno))

/*!
 * Peforms the same action as LOGE() except takes the error value for
 * strerror(3) as a parameter, instead of using errno(3)
 */
#define LOGSE(lvl, fmt, err, ...) \
    LOGFN((lvl), fmt ": %s", ##__VA_ARGS__, strerror(err))

/*!
 * Appends filename, line number and function name to the end of the entry
 * Example:
 *
 *      [INFO] Some informative message: main.c:25<thread_start>
 *
 *      where file -> main.c
 *            line -> 25
 *            func -> thread_start
 */
#define LOGFN(lvl, fmt, ...) \
    LOG((lvl), fmt ": %s:%u<%s>", ##__VA_ARGS__, __FILE__, __LINE__, __func__)

/*!
 * Generate log entry and write it to file
 */
void LOGF(FILE *file, loglvl_t level, const char *fmt, ...)
        __attribute__((__format__ (__printf__, 3, 4)));

void VLOGF(FILE *file, loglvl_t level, const char *fmt, va_list args)
        __attribute__((__format__ (__printf__, 3, 0)));

void TLOGF(FILE *file, loglvl_t level, struct timespec *t, const char *fmt,
           ...) __attribute__((__format__ (__printf__, 4, 5)));

void VTLOGF(FILE *file, loglvl_t level, struct timespec *ts, const char *fmt,
            va_list args) __attribute__((__format__ (__printf__, 4, 0)));

/*!
 * Append to a log transaction
 * @param trans transaction to append to
 */
void LOGT(struct log_trans *trans, const char *fmt, ...)
        __attribute__((__format__ (__printf__, 2, 3)));

void VLOGT(struct log_trans *trans, const char *fmt, va_list args)
        __attribute__((__format__ (__printf__, 2, 0)));

#define LOGTFN(t, fmt, ...) \
    LOGT((t), fmt ": %s:%u<%s>", ##__VA_ARGS__, __FILE__, __LINE__, __func__)

/*
 * Transactional logging
 */

/*!
 * Start a log transaction
 * @param level log level to use
 * @return a transaction structure
 */
#define LOG_TRANS(lvl) { .level = (lvl), .time = {0}, .str = NULL, .strsize = 0 }
#define PKT_TRANS(lvl) { .t = LOG_TRANS(lvl), .filter = LLIST_INITIALISER }

/*!
 * Commit log transaction to the standard streams
 * @param trans transaction to commit
 */
void LOGT_COMMIT(struct log_trans *trans);

#define LOGT_COMMITFN(t) \
    do { \
        LOGT((t), ": %s:%u<%s>", __FILE__, __LINE__, __func__); \
        LOGT_COMMIT(t); \
    } while (0)

/*!
 * Commit log transaction to a specific file
 * Calls LOGT_DISPOSE on transaction after it is committed
 * @param trans transaction to commit
 * @param file  file to write log transaction to
 */
void FLOG_COMMIT(struct log_trans *trans, FILE *file);

/*!
 * Disposes of dynamically allocated memory from calling LOGT()
 */
void LOGT_DISPOSE(struct log_trans *trans);

/*!
 * Optionally commit a log transaction, always disposing of it
 */
#define LOGT_OPT_COMMIT(opt, trans) \
    do { \
    if (opt) LOGT_COMMIT(trans); \
    else LOGT_DISPOSE(trans); \
    } while (0)

/*
 * Configuration functions
 */

#endif //NETSTACK_LOG_H
