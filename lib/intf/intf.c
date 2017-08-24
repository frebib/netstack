#include <libnet/intf/intf.h>

int if_type(struct intf *intf) {
    return intf->type;
}
