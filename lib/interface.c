#include <libnet/interface.h>
#include <libnet/eth/ether.h>

// TODO: Differentiate various interface types
void recv_if(struct interface *intf, struct frame *frame) {
    // TODO: Take different socket types into account here
    // e.g. TUN vs TAP, ignoring ETHER layer for example

    // TODO: For now, assume everything is ethernet
    recv_ether(intf, frame);

}