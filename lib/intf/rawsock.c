#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sysexits.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#include <linux/if_ether.h>
#include <libnet/eth/ether.h>
#include <libnet/intf/rawsock.h>

int new_rawsock(struct intf *interface) {
    if (interface == NULL) {
        return -1;
    }

    // Open a raw socket (raw layer 2/3 frames)
    // Use SOCK_DGRAM to remove ethernet header
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Error: could not create socket");
        return -1;
    }

    struct ifreq ifr;
    strcpy(ifr.ifr_name, INTF_NAME);
    // Get the current flags that the device might have
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
        perror("Error: Could not retrive the flags from the device.\n");
        return -1;
    }
    // Set the old flags plus the IFF_PROMISC flag
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
        perror("Error: Could not set flag IFF_PROMISC");
        return -1;
    }
    // Configure the device
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("Error: Error getting the device index.\n");
        return -1;
    }

    // Use container pointer to ensure int always fits
    // This also avoids lots of horrible type warnings
    int *sockptr = malloc(sizeof(int));
    *sockptr = sock;

    interface->intf_lower = sockptr;
    interface->type = INTF_RAWSOCK;
    interface->recv_frame = rawsock_recv_frame;
    interface->send_frame = rawsock_send_frame;
    interface->recv_peek = rawsock_peek;

    return 0;
}

void free_rawsock(struct intf *intf) {
    int *sockptr = (int *) intf->intf_lower;
    close(*sockptr);
    free(sockptr);
    free(intf);
}

ssize_t rawsock_recv_frame(struct intf *interface, struct frame **frame) {
    // Count is raw eth packet size (inc eth + ip + transport)
    ssize_t lookahead = 0,
            count = 0;
    int sock = *((int *) interface->intf_lower);

    // Use peek method in struct, it may have been overridden
    if ((lookahead = interface->recv_peek(interface)) == -1) {
        return lookahead;
    }

    // Allocate a buffer of the correct size
    *frame = init_frame(NULL, (size_t) lookahead);
    struct frame *eth_frame = *frame;

    // Read network data into the frame
    count = recv(sock, eth_frame->buffer, (size_t) lookahead, 0);

    // There was an error. errno should be set
    if (count == -1) {
        return count;
    }

    // Warn if the sizes don't match (should probably never happen)
    if (count != lookahead) {
        fprintf(stderr, "Warning: MSG_PEEK != recv(): %zi != %zi\n",
                lookahead, count);

        // TODO: Print debug messages for uncommon paths like these

        // realloc a (larger?) new buffer if the size differs, just in case
        void *newbuf;
        if ((newbuf = realloc(eth_frame->buffer, (size_t) count)) == NULL) {
            fprintf(stderr, "Fatal: Failed to reallocate new buffer of "
                    "size %zi bytes\n", count);
            exit(EX_OSERR);
        }
        eth_frame->buffer = newbuf;
    }

    return 0;
}

ssize_t rawsock_send_frame(struct intf *interface, struct frame *frame) {
    // TODO: Move this into a separate thread and use signalling
    int sock = *((int *) interface->intf_lower);
    return write(sock, frame->buffer, frame->buf_size);
}

ssize_t rawsock_peek(struct intf *interface) {
    int sock = *((int *) interface->intf_lower);
    return recv(sock, NULL, 0, (MSG_PEEK | MSG_TRUNC));
}
