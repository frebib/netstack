#ifndef NETSTACK_PROTO_H
#define NETSTACK_PROTO_H

/*
 * Common collection of protocols
 * that can be manipulated in software
 */

typedef enum proto {
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


#endif //NETSTACK_PROTO_H
