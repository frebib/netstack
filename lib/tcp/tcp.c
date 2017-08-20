#include <stdlib.h>
#include <netinet/in.h>

#include <libnet/tcp/tcp.h>

struct tcp_hdr *recv_tcp(struct frame *frame) {
    struct tcp_hdr *tcp_hdr = (struct tcp_hdr *) frame->data;

    tcp_hdr->sport = ntohs(tcp_hdr->sport);
    tcp_hdr->dport = ntohs(tcp_hdr->dport);
    tcp_hdr->seqn = ntohl(tcp_hdr->seqn);
    tcp_hdr->ackn = ntohl(tcp_hdr->ackn);
    tcp_hdr->wind = ntohs(tcp_hdr->wind);
    tcp_hdr->csum = ntohs(tcp_hdr->csum);
    tcp_hdr->urg_ptr = ntohs(tcp_hdr->urg_ptr);

    return tcp_hdr;
}
