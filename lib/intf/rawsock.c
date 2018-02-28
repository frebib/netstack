#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sysexits.h>
#include <errno.h>
#include <pthread.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>

#include <netstack/log.h>
#include <netstack/eth/ether.h>
#include <netstack/intf/rawsock.h>

int rawsock_new(struct intf *interface) {
    if (interface == NULL)
        return -EINVAL;

    // Open a raw socket (raw layer 2/3 frames)
    // Use SOCK_DGRAM to remove ethernet header
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        LOGERR("socket");
        return -1;
    }

    int opt = true;
    int err = setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPNS, &opt, sizeof(int));
    if (err < 0) {
        LOGERR("setsockopt SO_TIMESTAMPNS");
        close(sock);
        return -1;
    }

    // Request first non-loopback interface
    struct ifreq ifr = {0};
    struct if_nameindex *if_ni, *if_ni_head = if_nameindex();
    if_ni = if_ni_head;
    int ifrsock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP);
    while (if_ni != NULL && if_ni->if_index != 0) {

        strncpy(ifr.ifr_name, if_ni->if_name, IFNAMSIZ);
        if (ioctl(ifrsock, SIOCGIFFLAGS, &ifr)) {
            int err = errno;
            LOGERR("ioctl SIOCGIFFLAGS");
            if_freenameindex(if_ni_head);
            close(ifrsock);
            close(sock);
            return err;
        }
        // Check if the interface is 'up'
        if (ifr.ifr_flags & IFF_UP && !(ifr.ifr_flags & IFF_LOOPBACK))
            break;

        // Keep looking
        if_ni++;
    }
    close(ifrsock);

    if (if_ni == NULL) {
        close(sock);
        return -ENODEV;
    }

    memset(interface->name, 0, IFNAMSIZ);
    strncpy(interface->name, if_ni->if_name, IFNAMSIZ);
    uint32_t ifindex = if_ni->if_index;
    char *ifname = interface->name;
    if_freenameindex(if_ni_head);

    // Bind to specific interface to prevent duplicate packet reception
    struct sockaddr_ll sa_ll = {
            .sll_ifindex = ifindex,
            .sll_family = AF_PACKET
    };
    if (bind(sock, (struct sockaddr *) &sa_ll, sizeof(sa_ll))) {
        LOGERR("[RAWSOCK] bind");
        close(sock);
        return -1;
    }

    struct ifreq req = {0};
    strcpy(req.ifr_name, ifname);

    // Get chosen interface mac address
    if (ioctl(sock, SIOCGIFHWADDR, &req)) {
        close(sock);
        return -1;
    }
    uint8_t *hwaddr = malloc(IFHWADDRLEN);
    memcpy(hwaddr, req.ifr_addr.sa_data, IFHWADDRLEN);

    if (ioctl(sock, SIOCGIFMTU, &req)) {
        free(hwaddr);
        close(sock);
        return -1;
    }
    int mtu = req.ifr_mtu;

    LOG(LINFO, "Using interface (#%d) %s, mtu %d", ifindex, ifname, mtu);

    struct intf_rawsock *ll = malloc(sizeof(struct intf_rawsock));
    ll->sock = sock;
    ll->if_index = ifindex;

    interface->ll = ll;
    interface->ll_addr = hwaddr;
    interface->mtu = (size_t) mtu;
    interface->type = INTF_RAWSOCK;
    interface->proto = PROTO_ETHER;
    interface->free = rawsock_free;
    interface->recv_frame = rawsock_recv_frame;
    interface->send_frame = rawsock_send_frame;
    interface->new_buffer = intf_malloc_buffer;
    interface->free_buffer = intf_free_buffer;

    return 0;
}

void rawsock_free(struct intf *intf) {
    // TODO: Move some of this cleanup logic into a generic intf_free() function
    struct intf_rawsock *sockptr = (struct intf_rawsock *) intf->ll;
    close(sockptr->sock);
    free(sockptr);
    free(intf->ll_addr);
    llist_iter(&intf->arptbl, free);
    llist_clear(&intf->arptbl);
    llist_iter(&intf->inet, free);
    llist_clear(&intf->inet);
    // TODO: Ensure frames are destroyed, even if they still have references
    llist_iter(&intf->sendq, frame_decref);
}

long rawsock_recv_frame(struct frame *frame) {

    struct intf *interface = frame->intf;
    // Count is raw eth packet size (inc eth + ip + transport)
    ssize_t lookahead = 0,
            count = 0;
    int sock = *((int *) interface->ll);

    // Allow cancellation around peek() as this is the main blocking call
    pthread_cleanup_push((void (*)(void *)) frame_decref, frame) ;
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    // use MSG_PEEK to get lookahead amount available to recv
    if ((lookahead = recv(sock, NULL, 0, (MSG_PEEK | MSG_TRUNC))) == -1) {
        return (int) lookahead;
    }

    // Don't allow cancellation from here onwards
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_cleanup_pop(false);

    // TODO: Allocate a buffer from the interface for frame storage
    frame_init_buf(frame, malloc((size_t) lookahead), lookahead);
    frame->data = frame->buffer;

    // Allocate msghdr to receive packet & ancillary data into
    // TODO: Find an appropriate size for the control buffer
    uint8_t ctrl[1024];
    struct msghdr msgh = {0};
    struct iovec iov = {0};
    iov.iov_base = frame->data;
    iov.iov_len = (size_t) lookahead;
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = &ctrl;
    msgh.msg_controllen = 1024;

    // Read network data into the frame
    count = recvmsg(sock, &msgh, 0);

    // There was an error. errno should be set
    if (count == -1) {
        return (int) count;
    }

    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(&msgh);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
        if ((cmsg->cmsg_level == SOL_SOCKET)
            && (cmsg->cmsg_type == SO_TIMESTAMPNS))
            memcpy(&frame->time, CMSG_DATA(cmsg), sizeof(frame->time));
    }

    // Warn if the sizes don't match (should probably never happen)
    if (count != lookahead) {
        LOG(LWARN, "MSG_PEEK != recv(): %zi != %zi", lookahead, count);

        // realloc a (larger?) new buffer if the size differs, just in case
        void *newbuf;
        if ((newbuf = realloc(frame->buffer, (size_t) count)) == NULL) {
            LOG(LCRIT, "Failed to reallocate new buffer of %zi bytes", count);
            exit(EX_OSERR);
        }
        frame->buffer = newbuf;
        LOG(LNTCE, "realloc()'ed a new buffer of size %zi", count);
    }

    return count;
}

long rawsock_send_frame(struct frame *frame) {
    struct intf_rawsock *ll = (struct intf_rawsock *) frame->intf->ll;
    struct sockaddr_ll sa = {0};
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ll->if_index;
    sa.sll_halen = ETH_ADDR_LEN;
    memcpy(sa.sll_addr, eth_hdr(frame)->daddr, ETH_ADDR_LEN);

    ssize_t ret = sendto(ll->sock, frame->head, frame->tail - frame->head, 0,
                         (const struct sockaddr *) &sa, sizeof(sa));

    return ret < 0 ? errno : ret;
}
