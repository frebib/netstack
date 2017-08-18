#include <netinet/in.h>
#include <libnet/frame.h>
#include <libnet/eth/ether.h>

struct eth_hdr *recv_ether(struct frame *frame) {

    struct eth_hdr *hdr = (struct eth_hdr *) frame->buffer;
    hdr->ethertype = ntohs(hdr->ethertype);

    frame->data += ETH_HDR_LEN;

    return hdr;
}


