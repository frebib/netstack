#ifndef NETSTACK_PROTO_H
#define NETSTACK_PROTO_H

/*
 * Common collection of protocols
 * that can be manipulated in software
 */

typedef enum proto {

    PROTO_NULL      = 0,

    /* Hardware protocols (layer 2) */
    PROTO_ETHER     = 0x20,         /* Ethernet */
    PROTO_ETHER_VL  = 0x21,         /* Ethernet with 802.1q VLANs */

    /* Network protocols  (layer 3) */
    PROTO_IP        = 0x30,
    PROTO_IPV4      = 0x31,
    PROTO_IPV6      = 0x32,

    /* Transport protocols (layer 4) */
    PROTO_TCP       = 0x41,
    PROTO_UDP       = 0x42,
    PROTO_ICMP      = 0x43,

    /* ICMP control types */
    PROTO_ICMP_ECHO = 0x50,

} proto_t;


static inline char *strproto(proto_t proto) {
    switch (proto) {

        /* Hardware protocols (layer 2) */
        case PROTO_ETHER:       return "ether";
        case PROTO_ETHER_VL:    return "ether VLAN";

        /* Network protocols  (layer 3) */
        case PROTO_IP:          return "IP";
        case PROTO_IPV4:        return "IPv4";
        case PROTO_IPV6:        return "IPv6";

        /* Transport protocols (layer 4) */
        case PROTO_TCP:         return "TCP";
        case PROTO_UDP:         return "UDP";
        case PROTO_ICMP:        return "ICMP";

        /* ICMP control types */
        case PROTO_ICMP_ECHO:   return "ICMP Echo";

        case PROTO_NULL:
        default:                return NULL;
    }
}


#endif //NETSTACK_PROTO_H
