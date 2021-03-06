#ifndef NETSTACK_LOG_H
#define NETSTACK_LOG_H

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

#include <netstack/col/llist.h>

#define LOG_TRANS_INIT_BUFFER   64      /* Initial log_trans buffer size */
// TODO: Make LOG_MAX configurable
#define LOG_MAX                 1024    /* Maximum log entry length */

#ifndef NETSTACK_LOG_UNIT
    #define LOG_UNIT ""
#else
    #define LOG_UNIT "("NETSTACK_LOG_UNIT") "
#endif

typedef uint8_t loglvl_t;

/* 2^n where n is size of loglvl_t, times 8 bits per byte */
#define loglvl_max (1 << (sizeof(loglvl_t) * 8)) /* Max amount of log levels */

struct log_config {
    llist_t streams;            /* Standard logging output */
    char *lvlstr[loglvl_max];   /* String representations of log levels */
    char *lvlcol[loglvl_max];   /* String representations of log levels */
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
 * Global logging configuration
 */
extern struct log_config logconf;


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


#define ANSI_ESC            "\033["
#define ANSI_BOLD           "1;"
#define ANSI_ITALIC         "3;"
#define ANSI_UNDERLN        "4;"

#define ANSI_RED            "31m"
#define ANSI_GREEN          "32m"
#define ANSI_YELLOW         "33m"
#define ANSI_BLUE           "34m"
#define ANSI_MAGENTA        "35m"
#define ANSI_CYAN           "36m"
#define ANSI_GRAY           "37m"

#define ANSI_BRIGHT_RED     "91m"
#define ANSI_BRIGHT_GREEN   "92m"
#define ANSI_BRIGHT_YELLOW  "93m"
#define ANSI_BRIGHT_BLUE    "94m"
#define ANSI_BRIGHT_MAGENTA "95m"
#define ANSI_BRIGHT_CYAN    "96m"
#define ANSI_BRIGHT_GRAY    "97m"

#define COLOR_RED            ANSI_ESC ANSI_RED
#define COLOR_GREEN          ANSI_ESC ANSI_GREEN
#define COLOR_YELLOW         ANSI_ESC ANSI_YELLOW
#define COLOR_BLUE           ANSI_ESC ANSI_BLUE
#define COLOR_MAGENTA        ANSI_ESC ANSI_MAGENTA
#define COLOR_CYAN           ANSI_ESC ANSI_CYAN
#define COLOR_GRAY           ANSI_ESC ANSI_GRAY

#define COLOR_BRIGHT_RED     ANSI_ESC ANSI_BRIGHT_RED
#define COLOR_BRIGHT_GREEN   ANSI_ESC ANSI_BRIGHT_GREEN
#define COLOR_BRIGHT_YELLOW  ANSI_ESC ANSI_BRIGHT_YELLOW
#define COLOR_BRIGHT_BLUE    ANSI_ESC ANSI_BRIGHT_BLUE
#define COLOR_BRIGHT_MAGENTA ANSI_ESC ANSI_BRIGHT_MAGENTA
#define COLOR_BRIGHT_CYAN    ANSI_ESC ANSI_BRIGHT_CYAN
#define COLOR_BRIGHT_GRAY    ANSI_ESC ANSI_BRIGHT_GRAY

#define COLOR_RESET   "\x1b[0m"


/*!
 * Initialise log_config with stdout and stderr default log streams
 */
void log_default(struct log_config *conf);

/*!
 * Generate log entry
 */
extern void _LOG(loglvl_t level, const char *fmt, ...)
        __attribute__((__format__ (__printf__, 2, 3)));

void VLOG(loglvl_t level, const char *fmt, va_list args)
        __attribute__((__format__ (__printf__, 2, 0)));

void TLOG(loglvl_t level, struct timespec *t, const char *fmt, ...)
        __attribute__((__format__ (__printf__, 3, 4)));

void VTLOG(loglvl_t level, struct timespec *t, const char *fmt, va_list args)
        __attribute__((__format__ (__printf__, 3, 0)));

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
#define LOG(lvl, fmt, ...) \
    _LOG((lvl), "%s" fmt ": %s:%u<%s>", LOG_UNIT, ##__VA_ARGS__, \
            __FILE__, __LINE__, __func__)

/*!
 * Equivalent of perror(3)
 * Calls LOG() to add file, line and function to log entry
 */
#define LOGERR(fmt, ...) \
    LOG(LERR,  fmt ": %s", ##__VA_ARGS__, strerror(errno))

/*!
 * Performs the same action as LOGERR() but takes the log level as a
 * parameter instead of defaulting to LERR
 */
#define LOGE(lvl, fmt, ...) \
    LOG((lvl), fmt ": %s", ##__VA_ARGS__, strerror(errno))

/*!
 * Peforms the same action as LOGE() except takes the error value for
 * strerror(3) as a parameter, instead of using errno(3)
 */
#define LOGSE(lvl, fmt, err, ...) \
    LOG((lvl), fmt ": %s", ##__VA_ARGS__, strerror(err))

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


/*
 * Transactional logging
 */

/*!
 * Start a log transaction
 * @param level log level to use
 * @return a transaction structure
 */
#define LOG_TRANS(lvl) { .level = (lvl), .time = {0}, .str = strdup(LOG_UNIT), .strsize = 0 }
#define PKT_TRANS(lvl) { .t = LOG_TRANS(lvl), .filter = LLIST_INITIALISER }

/*!
 * Commit log transaction to the standard streams
 * @param trans transaction to commit
 */
extern void _LOGT_COMMIT(struct log_trans *trans);

#define LOGT_COMMIT(t) \
    do { \
        LOGT((t), ": %s:%u<%s>", __FILE__, __LINE__, __func__); \
        _LOGT_COMMIT(t); \
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
    if (opt) _LOGT_COMMIT(trans); \
    else LOGT_DISPOSE(trans); \
    } while (0)

/*
 * Configuration functions
 */

#endif //NETSTACK_LOG_H
