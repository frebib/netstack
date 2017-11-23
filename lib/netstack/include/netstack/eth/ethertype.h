#ifndef NETD_ETHERTYPE_H
#define NETD_ETHERTYPE_H

/* IEEE registered ethertypes:
 http://standards-oui.ieee.org/ethertype/eth.txt */

#include <stddef.h>

#define ETH_P_ARP   0x0806  /* Address Resolution Protocol */
#define ETH_P_IP    0x0800  /* Internet Protocol Version 4 */
#define ETH_P_IPV6  0x86DD  /* Internet Protocol Version 6 */

#define ETH_P_LLDP  0x88CC  /* Link Layer Discovery Protocol */


/* Returns a matching `const char *` to a ETH_P_* value */
static inline char const *fmt_ethertype(unsigned short ethertype) {
    switch (ethertype) {
        case ETH_P_IP:      return "ETH_P_IP";
        case ETH_P_IPV6:    return "ETH_P_IPV6";
        case ETH_P_ARP:     return "ETH_P_ARP";
        case ETH_P_LLDP:    return "ETH_P_LLDP";
        default:            return NULL;
    }
}

#endif //NETD_ETHERTYPE_H
