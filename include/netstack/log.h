#ifndef NETSTACK_LOG_H
#define NETSTACK_LOG_H

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

#include <netstack/llist.h>

#define LOG_TRANS_INIT_BUFFER   64      /* Initial log_trans buffer size */

/*
 * Global logging configuration
 */
extern struct log_config logconf;

typedef uint8_t loglvl_t;

/* 2^n where n is size of loglvl_t, times 8 bits per byte */
#define loglvl_max (1 << (sizeof(loglvl_t) * 8)) /* Max amount of log levels */

struct log_config {
    struct llist streams;       /* Standard logging output */
    char *lvlstr[loglvl_max];   /* String representations of log levels */
};

struct log_stream {
    FILE *stream;       /* Stream to write log entries to */
    loglvl_t min;       /* Minimum log level for stream (inclusive) */
    loglvl_t max;       /* Maximum log level for stream (inclusive) */
};

struct log_trans {
    loglvl_t level;
    struct timespec time;   /* Time to print before log entry. Defaults to null
                               in which case commit time will be used */
    char *str;          /* Transaction string buffer */
    size_t strsize;     /* Allocated size of str*/
};

struct pkt_log {
    struct log_trans t; /* Log transaction to write to */
    struct llist filter;/* List of options, similar to those in * tcpdump */
};

/*
 * Default log levels
 */
#define LCRIT 0xF0
#define LERR  0xC0
#define LWARN 0xA0
#define LNTCE 0x80
#define LINFO 0x60
#define LDBUG 0x40
#define LTRCE 0x20
#define LNULL 0x00

#define logcrit(...) log(LCRIT, __VA_ARGS__)
#define logerr(...)  log(LERR,  __VA_ARGS__)
#define logwarn(...) log(LWARN, __VA_ARGS__)
#define logntce(...) log(LNTCE, __VA_ARGS__)
#define loginfo(...) log(LINFO, __VA_ARGS__)
#define logdbug(...) log(LDBUG, __VA_ARGS__)
#define logtrce(...) log(LTRCE, __VA_ARGS__)


// macros: __FILE__, __LINE__, __func__

/*!
 * Initialise log_config with stdout and stderr default log streams
 */
void log_default(void);

/*!
 * Generate log entry
 */
void LOG(loglvl_t level, const char *fmt, ...);
void VLOG(loglvl_t level, const char *fmt, va_list args);
void TLOG (loglvl_t level, struct timespec *t, const char *fmt, ...);
void VTLOG(loglvl_t level, struct timespec *t, const char *fmt, va_list args);

/*!
 * Generate log entry and write it to file
 */
void LOGF(FILE *file, loglvl_t level, const char *fmt, ...);
void VLOGF(FILE *file, loglvl_t level, const char *fmt, va_list args);
void TLOGF(FILE *file, loglvl_t level, struct timespec *t, const char *fmt,
           ...);
void VTLOGF(FILE *file, loglvl_t level, struct timespec *ts, const char *fmt,
            va_list args);

/*!
 * Append to a log transaction
 * @param trans transaction to append to
 */
void LOGT(struct log_trans *trans, const char *fmt, ...);
void VLOGT(struct log_trans *trans, const char *fmt, va_list args);

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

/*
 * Configuration functions
 */

#endif //NETSTACK_LOG_H
