#ifndef NETSTACK_PROTO_H
#define NETSTACK_PROTO_H

/*
 * Common collection of protocols
 * that can be manipulated in software
 */

/* Hardware protocols (layer 1) */
#define PROTO_ETHER     0x01

/* Network protocols (layer 2) */
#define PROTO_IP        0x12
#define PROTO_IPV4      0x13
#define PROTO_IPV6      0x14

/* Transport protocols (layer 3) */
#define PROTO_TCP       0x20
#define PROTO_UDP       0x21
#define PROTO_ICMP      0x22


#endif //NETSTACK_PROTO_H
