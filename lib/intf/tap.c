#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <linux/if_tun.h>

#define NETSTACK_LOG_UNIT "TAP"
#include <netstack/log.h>
#include <netstack/intf/tap.h>
#include <netstack/eth/ether.h>


int tap_new(struct intf *interface) {
    if (interface == NULL)
        return EINVAL;

    int fd;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return fd;
    }

    struct ifreq req = {0};
    // IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI
    req.ifr_flags = IFF_TAP | IFF_NO_PI;

    // TODO: Allow TUN/TAP name configuration
    char *devname = "netstack";
    strncpy(req.ifr_name, devname, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &req)) {
        LOGERR("ioctl TUNSETIFF");
        close(fd);
        return errno;
    }

    memset(&req, 0, sizeof(struct ifreq));
    strncpy(req.ifr_name, devname, IFNAMSIZ);

    if (ioctl(fd, SIOCGIFMTU, &req)) {
        LOGERR("ioctl SIOCGIFMTU");
//        close(fd);
//        return errno;
    }
    // TODO: Fix TUN/TAP SIOCGIFMTU: EINVAL
//    int mtu = req.ifr_mtu;
    int mtu = 1500;

    LOG(LINFO, "Using interface (#%d) %s, mtu %d",
        req.ifr_ifindex, devname, mtu);

    if (ioctl(fd, SIOCGIFHWADDR, &req) < 0) {
        LOGERR("ioctl SIOCGIFHWADDR");
        return errno;
    }

    uint8_t *hwaddr = malloc(ETH_ADDR_LEN);
    for (int i = 0; i < ETH_ADDR_LEN; ++i)
        hwaddr[i] = (uint8_t) req.ifr_hwaddr.sa_data[i];

    int *ll = malloc(sizeof(int));
    *ll = fd;
    interface->ll = ll;
    interface->ll_addr = hwaddr;
    interface->mtu = (size_t) mtu;
    // Zero then copy interface name
    memset(interface->name, 0, IFNAMSIZ);
    strncpy(interface->name, devname, IFNAMSIZ);
    interface->type = INTF_TAP;
    interface->proto = PROTO_ETHER;
    interface->free = tap_free;
    interface->recv_frame = tap_recv_frame;
    interface->send_frame = tap_send_frame;
    interface->new_buffer = intf_malloc_buffer;
    interface->free_buffer = intf_free_buffer;

    return 0;
}

void tap_free(struct intf *intf) {

}

long tap_recv_frame(struct frame *frame) {

    struct intf *interface = frame->intf;
    // Count is raw eth packet size (inc eth + ip + trans:port)
    ssize_t count = 0;
    int sock = *((int *) interface->ll);

    // TODO: Check for IFF_PI and allocate space for it
    size_t size = interface->mtu + sizeof(struct eth_hdr_vlan) + 4;
    frame_init_buf(frame, malloc(size), size);
    frame->data = frame->buffer;

    // Allow cancellation around peek() as this is the main blocking call
    pthread_cleanup_push((void (*)(void *)) frame_decref, frame) ;
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    if ((count = read(sock, frame->buffer, frame->buf_sz)) == -1)
        return (int) count;

    // Don't allow cancellation from here onwards
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_cleanup_pop(false);

    return count;
}

long tap_send_frame(struct frame *frame) {
    struct intf *interface = frame->intf;
    int sock = *((int *) interface->ll);

    ssize_t count = 0;
    size_t len = frame_pkt_len(frame);

    if ((count = write(sock, frame->head, len)) == -1) {
        LOGERR("write");
        return errno;
    }

    if (count != len)
        LOG(LWARN, "write() -> count != len");

    return 0;
}
