#include <stddef.h>
#include "ether.h"

const char const *fmt_ethertype(unsigned short ethertype) {
    switch (ethertype) {
        case ETH_P_IP:      return "ETH_P_IP";
        case ETH_P_IPV6:    return "ETH_P_IPV6";
        case ETH_P_ARP:     return "ETH_P_ARP";
        case ETH_P_LLDP:    return "ETH_P_LLDP";
        default:
            return NULL;
    }
}
