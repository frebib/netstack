#ifndef NETD_INTERFACE_H
#define NETD_INTERFACE_H

#include <sys/types.h>
#include <libnet/frame.h>

#define INTF_RAWSOCK    1
#define INTF_TUNTAP     2

// TODO: Implement 'virtual' network interfaces
// `man netdevice` gives a good overview
struct intf {
    uint8_t type;
    void *intf_lower;

    /* Blocking function call that reads a frame from the interface. */
    ssize_t (*recv_frame)(struct intf *, struct frame **);

    /* Blocking function call to send an entire frame to the interface */
    ssize_t (*send_frame)(struct intf *, struct frame *);

    ssize_t (*recv_peek)(struct intf *);

    void (*free)(struct intf *);
};

int if_type(struct intf *intf);

#endif //NETD_INTERFACE_H
