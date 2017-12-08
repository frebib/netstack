#ifndef NETSTACK_INTERFACE_H
#define NETSTACK_INTERFACE_H

#include <net/if.h>
#include <sys/types.h>

#include <netstack/frame.h>
#include <netstack/llist.h>

// Interface types
#define INTF_RAWSOCK    1
#define INTF_TUNTAP     2

// Interface thread ids
#define INTF_THR_RECV   0
#define INTF_THR_SEND   1
#define INTF_THR_MAX    2

// TODO: Implement 'virtual' network interfaces
// `man netdevice` gives a good overview
struct intf {
    uint8_t type;
    // Link layer information
    char name[IFNAMSIZ];
    void *ll;
    uint8_t *ll_addr;

    // TODO: Move this into an 'ethernet' hardware struct into `void *ll`
    struct llist_elem *arptbl;

    // Interface send/recv thread ids
    pthread_t threads[INTF_THR_MAX];

    // Blocking function call that reads a frame from the interface.
    ssize_t (*recv_frame)(struct intf *, struct frame **);

    ssize_t (*send_frame)(struct intf *, struct frame *);

    // Peeks at the amount of bytes available, or 0 if no frame available
    // Returns -1 on error
    ssize_t (*recv_peek)(struct intf *);

    // Cleans up an allocated interface data, excluding the interface struct
    // itself (may not have been dynamically allocated)
    void (*free)(struct intf *);

    // Stack input for recv'd data
    // Called by the interface with the appropriate frame type
    // e.g. ether frames for an ethernet device, IP frames for TUN
    void (*input)(struct intf *, struct frame *);
};

int if_type(struct intf *intf);

int init_intf(struct intf *intf);

#endif //NETSTACK_INTERFACE_H
