#ifndef NETSTACK_H
#define NETSTACK_H

#include <netstack/log.h>
#include <netstack/col/llist.h>


#define NETSTACK_VERSION    "0.0.1"


// Frame log level for packet dumps
#define LFRAME  0x0A

struct netstack {
    llist_t interfaces;
};


void netstack_init(struct netstack *inst);

void netstack_cleanup(struct netstack *inst);

/*!
 * Checks for sufficient capabilities for netstack operation
 * If any capabilities are not held then an error message is logged
 * @param name binary name/path to use in error messages
 * @return 0 on success, -1 otherwise
 */
int netstack_checkcap(const char *name);

#endif //NETSTACK_H
