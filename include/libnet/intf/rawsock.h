#ifndef NETD_RAWSOCK_H
#define NETD_RAWSOCK_H

#include <stddef.h>
#include <stdbool.h>

#include "intf.h"

struct intf_rawsock {
    int sock;
    int if_index;
};

int new_rawsock(struct intf *interface);

void free_rawsock(struct intf *interface);

ssize_t rawsock_recv_frame(struct intf *, struct frame **);

ssize_t rawsock_send_frame(struct intf *, struct frame *);

ssize_t rawsock_peek(struct intf *);

#endif //NETD_RAWSOCK_H
