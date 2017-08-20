#ifndef NETD_INTERFACE_H
#define NETD_INTERFACE_H

#include <libnet/frame.h>

// TODO: Implement 'virtual' network interfaces
// `man netdevice` gives a good overview
struct interface {

};

void recv_if(struct interface *intf, struct frame *frame);

#endif //NETD_INTERFACE_H
