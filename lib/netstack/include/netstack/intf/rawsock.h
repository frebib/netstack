#ifndef NETSTACK_RAWSOCK_H
#define NETSTACK_RAWSOCK_H

#include <stddef.h>
#include <stdbool.h>

#include <netstack/intf/intf.h>

/*
 * Taken from glibc net/if.h which conflicts with linux/if.h
 * https://github.com/mininet/openflow/blob/9f587fc8e657a248d46b4763cc7e72efaccf8e00/lib/netdev.c#L88-L90
 */

#ifndef _NET_IF_H
#define _NET_IF_H
struct if_nameindex {
    unsigned int if_index;  /* 1, 2, ... */
    char *if_name;          /* null terminated name: "eth0", ... */
};

/* Return a list of all interfaces and their indices.  */
extern struct if_nameindex *if_nameindex (void);

/* Free the data returned from if_nameindex.  */
extern void if_freenameindex (struct if_nameindex *__ptr);
#endif


struct intf_rawsock {
    int sock;
    int if_index;
};

int new_rawsock(struct intf *interface);

void free_rawsock(struct intf *interface);

ssize_t rawsock_recv_frame(struct intf *, struct frame **);

ssize_t rawsock_send_frame(struct intf *, struct frame *);

ssize_t rawsock_peek(struct intf *);

#endif //NETSTACK_RAWSOCK_H
