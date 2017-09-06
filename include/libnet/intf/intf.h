#ifndef NETD_INTERFACE_H
#define NETD_INTERFACE_H

#include <net/if.h>
#include <sys/types.h>

#include <libnet/frame.h>

// Interface types
#define INTF_RAWSOCK    1
#define INTF_TUNTAP     2

// TODO: Implement 'virtual' network interfaces
// `man netdevice` gives a good overview
struct intf {
    uint8_t type;
    // Link layer information
    char name[IFNAMSIZ];
    void *ll;
    uint8_t *ll_addr;

    // Blocking function call that reads a frame from the interface.
    ssize_t (*recv_frame)(struct intf *, struct frame **);

    ssize_t (*send_frame)(struct intf *, struct frame *);

    // Peeks at the amount of bytes available, or 0 if no frame available
    // Returns -1 on error
    ssize_t (*recv_peek)(struct intf *);

    // Cleans up an allocated interface data, excluding the interface struct
    // itself (may not have been dynamically allocated)
    void (*free)(struct intf *);
};

int if_type(struct intf *intf);

#endif //NETD_INTERFACE_H
