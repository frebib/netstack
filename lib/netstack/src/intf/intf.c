#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>

#include <netstack/intf/intf.h>

int if_type(struct intf *intf) {
    return intf->type;
}

void intf_send(struct intf *intf) {
    return;
}

void intf_recv(struct intf *intf) {
    struct frame *rawframe = NULL;
    ssize_t count;

    // When run as a thread, pthread_cancel() should be used to cancel this
    // execution so the cleanup routines are run, freeing allocated memory
    pthread_cleanup_push(free, rawframe);

    while ((count = intf->recv_frame(intf, &rawframe)) != -1) {
        // Capture time as packet is read
        struct timespec ts;
        // TODO: Implement rx 'software' timestamping
        if (false) {
            timespec_get(&ts, TIME_UTC);
        } else {
            ts = rawframe->time;
        }

        // TODO: Use logging
        // TODO: Conditionally print debugging information
        // Format and print time the same as tcpdump for comparison
        char buf[15];
        strftime(buf, sizeof(buf), "%T", gmtime(&ts.tv_sec));
        snprintf(buf + 8, 8, ".%ld", ts.tv_nsec);
        printf("%s ", buf);

        // Push received data into the stack
        intf->input(intf, rawframe);

        printf("\n");

        free_frame(rawframe);
    }

    // Run cleanup if rawframe was allocated
    pthread_cleanup_pop(rawframe != NULL);

    if (count == -1) {
        perror("recv error");
    }
}

int nthread_create(pthread_t *id, char *name,
                   void (*fn)(struct intf *), void *arg) {
    // Create and start thread
    int ret = pthread_create(id, NULL, (void *(*)(void *)) fn, arg);
#ifdef _GNU_SOURCE
    // Set the thread name, if available
    pthread_setname_np(*id, name);
#endif

    return ret;
}

int init_intf(struct intf *intf) {
    if (intf == NULL) {
        errno = EINVAL;
        return -1;
    }

    // Create threads
    pthread_t *th_ids = intf->threads;
    nthread_create(&th_ids[INTF_THR_SEND], "send", &intf_send, intf);
    nthread_create(&th_ids[INTF_THR_RECV], "recv", &intf_recv, intf);

    intf->arptbl = NULL;

    return 0;
}

