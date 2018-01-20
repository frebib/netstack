#ifndef NETSTACK_H
#define NETSTACK_H

// Frame log level for packet dumps
#define LFRAME  0x10


int netstack_init(void);

/*!
 * Checks for sufficient capabilities for netstack operation
 * If any capabilities are not held then an error message is logged
 * @param name binary name/path to use in error messages
 * @return 0 on success, -1 otherwise
 */
int netstack_checkcap(const char *name);

#endif //NETSTACK_H
