#ifndef NETSTACK_TAP_H
#define NETSTACK_TAP_H

#include <stddef.h>
#include <stdbool.h>

#include <netstack/intf/intf.h>

struct intf_tap {
};

int tap_new(struct intf *interface);

void tap_free(struct intf *intf) ;

long tap_recv_frame(struct frame *frame) ;

long tap_send_frame(struct frame *frame) ;

#endif //NETSTACK_TAP_H
