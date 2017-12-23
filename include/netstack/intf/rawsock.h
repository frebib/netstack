#ifndef NETSTACK_RAWSOCK_H
#define NETSTACK_RAWSOCK_H

#include <stddef.h>
#include <stdbool.h>

#include <netstack/intf/intf.h>

struct intf_rawsock {
    int sock;
    int if_index;
};

int rawsock_new(struct intf *interface);

void rawsock_free(struct intf *interface);

long rawsock_recv_frame(struct frame *);

long rawsock_send_frame(struct frame *);

int rawsock_peek(struct intf *);

#endif //NETSTACK_RAWSOCK_H
