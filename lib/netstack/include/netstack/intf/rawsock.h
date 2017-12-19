#ifndef NETSTACK_RAWSOCK_H
#define NETSTACK_RAWSOCK_H

#include <stddef.h>
#include <stdbool.h>

#include "intf.h"

struct intf_rawsock {
    int sock;
    int if_index;
};

int rawsock_new(struct intf *interface);

void rawsock_free(struct intf *interface);

ssize_t rawsock_recv_frame(struct intf *, struct frame **);

ssize_t rawsock_send_frame(struct intf *, struct frame *);

ssize_t rawsock_peek(struct intf *);

#endif //NETSTACK_RAWSOCK_H
