#ifndef NETD_IP_PROTO_H
#define NETD_IP_PROTO_H

/*
 * IP packet field protocol values
 * https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
 * https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 */

#define IP_P_ICMP   0x01
#define IP_P_IGMP   0x02
#define IP_P_TCP    0x06
#define IP_P_UDP    0x11

/* Returns a matching `const char *` to a IP_P_* value */
static inline char const *fmt_ipproto(unsigned short proto) {
    switch (proto) {
        case IP_P_ICMP:     return "IP_P_ICMP";
        case IP_P_IGMP:     return "IP_P_IGMP";
        case IP_P_TCP:      return "IP_P_TCP";
        case IP_P_UDP:      return "IP_P_UDP";
        default:            return NULL;
    }
}

#endif //NETD_IP_PROTO_H
