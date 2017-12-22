#ifndef NETSTACK_INTERFACE_H
#define NETSTACK_INTERFACE_H

#include <stdbool.h>
#include <semaphore.h>
#include <net/if.h>
#include <sys/types.h>

#include <netstack/addr.h>
#include <netstack/frame.h>
#include <netstack/llist.h>

// Fix circular include issue
struct frame;

// Interface types
#define INTF_RAWSOCK    0x01
#define INTF_TUNTAP     0x02

// Interface thread ids
#define INTF_THR_RECV   0x00
#define INTF_THR_SEND   0x01
#define INTF_THR_MAX    0x02

// TODO: Implement 'virtual' network interfaces
// `man netdevice` gives a good overview
struct intf {
    uint8_t type;
    uint8_t proto;          /* Defines the protocol running in the interface */
    // Link layer information
    char name[IFNAMSIZ];
    void *ll;
    uint8_t *ll_addr;
    size_t mtu;

    // Internet Addresses (IPv4/6)
    struct llist inet;

    // TODO: Move arptbl into an 'ethernet' hardware struct into `void *ll`
    struct llist arptbl;

    // Concurrency locking for send queue
    sem_t sendctr;
    pthread_mutex_t sendqlck;
    struct llist sendq;

    // Interface send/recv thread ids
    pthread_t threads[INTF_THR_MAX];

    // Blocking function call that reads a frame from the interface.
    /* Implementing method is responsible for populating frame->buffer using
     * frame_init_buf() and providing a suitable frame buffer (can be using
     * malloc) */
    int (*recv_frame)(struct frame *);

    int (*send_frame)(struct frame *);

    void *(*new_buffer)(struct intf *intf, size_t size);

    void (*free_buffer)(struct intf *intf, void *buffer);

    // Cleans up an allocated interface data, excluding the interface struct
    // itself (may not have been dynamically allocated)
    void (*free)(struct intf *);
};

/*!
 *
 * @param frame
 * @return
 */
int intf_dispatch(struct frame *frame);

/*!
 *
 * @param intf
 * @return
 */
int intf_init(struct intf *intf);

/*!
 *
 * @param frame
 * @param buf_size
 * @return
 */
struct frame *intf_frame_new(struct intf *frame, size_t buf_size);

/*!
 * Frees a frame and it's enclosed buffer
 * Assumes frame->intf is populated with the interface..
 * (if not, just use frame_free() as there should be no buffer assigned)
 * @param frame frame and enclosing buffer to free(3)
 */
void intf_frame_free(struct frame * frame);

/*!
 *
 * @param intf
 * @param size
 * @return
 */
void *intf_malloc_buffer(struct intf *intf, size_t size);

/*!
 *
 * @param intf
 * @param buffer
 */
void intf_free_buffer(struct intf *intf, void *buffer);

/*!
 * Checks whether an interface has the specified address
 * @param intf interface to check
 * @param addr address & protocol to check
 * @return true if requested protocol and address match
 */
bool intf_has_addr(struct intf *intf, addr_t *addr);

#endif //NETSTACK_INTERFACE_H
