#include <stdlib.h>

#include <sys/capability.h>

#define NETSTACK_LOG_UNIT "NETSTACK"
#include <netstack.h>
#include <netstack/log.h>
#include <netstack/intf/intf.h>


void netstack_init(struct netstack *inst) {
    // Initialise default logging with stdout & stderr
    log_default(&logconf);
    logconf.lvlstr[LFRAME] = "FRAME";
    struct log_stream *fr = malloc(sizeof(struct log_stream));
    fr->stream = stdout;
    fr->min = LFRAME;
    fr->max = LFRAME;
    llist_append(&logconf.streams, fr);
}

void netstack_cleanup(struct netstack *inst) {
    for_each_llist(&inst->interfaces) {
        struct intf *intf = llist_elem_data();
        LOG(LINFO, "Cleaning up interface %s", intf->name);
        intf->free(intf);
    }
}

int netstack_checkcap(const char *name) {
    // Check for effective CAP_NET_RAW,CAP_NET_ADMIN capabilities
    cap_flag_value_t hasRaw = CAP_CLEAR;
    cap_flag_value_t hasAdmin = CAP_CLEAR;
    cap_t capabilities = cap_get_proc();
    if (cap_get_flag(capabilities, CAP_NET_RAW, CAP_EFFECTIVE, &hasRaw) ||
        cap_get_flag(capabilities, CAP_NET_ADMIN, CAP_EFFECTIVE, &hasAdmin)) {
        LOG(LERR, "Error checking capabilities");
    }
    cap_free(capabilities);

    // Check and error if capabilities aren't set
    if (hasRaw != CAP_SET) {
        LOG(LCRIT, "You don't have the CAP_NET_RAW capability.\n"
                "Use 'setcap cap_net_raw+ep %s' or run as root", name);
        return -1;
    } else if (hasAdmin != CAP_SET) {
        LOG(LCRIT, "You don't have the CAP_NET_ADMIN capability.\n"
                "Use 'setcap cap_net_admin+ep %s' or run as root", name);
        return -1;
    }

    return 0;
}
