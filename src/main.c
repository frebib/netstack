#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <sysexits.h>

#include <sys/capability.h>
#include <linux/if_ether.h>

#include <libnet/frame.h>
#include <libnet/eth/ether.h>
#include <libnet/eth/arp.h>
#include <libnet/ip/ipv4.h>
#include <libnet/tcp/tcp.h>
#include <libnet/intf/rawsock.h>

int main(int argc, char **argv) {

    // Check for effective CAP_NET_RAW,CAP_NET_ADMIN capabilities
    cap_flag_value_t hasRaw = CAP_CLEAR,
            hasAdmin = CAP_CLEAR;
    cap_t capabilities = cap_get_proc();
    if (cap_get_flag(capabilities, CAP_NET_RAW, CAP_EFFECTIVE, &hasRaw) ||
        cap_get_flag(capabilities, CAP_NET_ADMIN, CAP_EFFECTIVE, &hasAdmin)) {
        perror("Error checking capabilities");
    }
    cap_free(capabilities);

    // Check and error if capabilities aren't set
    if (hasRaw != CAP_SET) {
        fprintf(stderr, "You don't have the CAP_NET_RAW capability.\n"
                "Use 'setcap cap_net_raw+ep %s' or run as root\n", argv[0]);
        exit(1);
    } else if (hasAdmin != CAP_SET) {
        fprintf(stderr, "You don't have the CAP_NET_ADMIN capability.\n"
                "Use 'setcap cap_net_admin+ep %s' or run as root\n", argv[0]);
        exit(1);
    }

    // Create a INTF_RAWSOCK interface for sending/recv'ing data
    struct intf *intf = malloc(sizeof(struct intf));
    struct frame *eth_frame = NULL;
    ssize_t count;

    // TODO: Take different socket types into account here
    // e.g. TUN vs TAP, ignoring ETHER layer for example
    // TODO: For now, assume everything is ethernet
    if (new_rawsock(intf) != 0) {
        perror("Error creating INTF_RAWSOCK");
        return EX_IOERR;
    }

    // Read data into the buffer
    while ((count = intf->recv_frame(intf, &eth_frame)) != -1) {
        struct timespec ts;
        timespec_get(&ts, TIME_UTC);

        // Packet received. Notify the virtual 'interface' for processing
        recv_ether(intf, eth_frame);

        struct eth_hdr *ethhdr = eth_hdr(eth_frame);
        if (memcmp(ethhdr->daddr, intf->ll_addr, ETH_ADDR_LEN) != 0) {
            goto cleanup;
        }

        // Format and print time the same as tcpdump for comparison
        char buf[15];
        strftime(buf, sizeof(buf), "%T", gmtime(&ts.tv_sec));
        snprintf(buf + 8, 8, ".%ld", ts.tv_nsec);
        // Print time received and payload size
        printf("%s Received a frame of %5lu bytes\t\n", buf, count);
        /*
         * ETHERNET
         */
        char ssaddr[18], sdaddr[18];
        fmt_mac(ethhdr->saddr, ssaddr);
        fmt_mac(ethhdr->daddr, sdaddr);
        printf("==> Ethernet Frame\n");
        printf("\tSource: %s\n\tDest:   %s\n\tType:   0x%04X > %s\n",
               ssaddr, sdaddr, ethhdr->ethertype,
               fmt_ethertype(ethhdr->ethertype));

        /*
         * ARP
         */
        if (ethhdr->ethertype == ETH_P_ARP) {
            struct frame *arp_frame = eth_frame->child;
            struct arp_hdr *msg = arp_hdr(arp_frame);
            struct arp_ipv4 *req = (struct arp_ipv4 *) arp_frame->data;

            char ssmac[18], sdmac[18];
            char ssipv4[16], sdipv4[16];
            fmt_mac(req->saddr, ssmac);
            fmt_mac(req->daddr, sdmac);
            fmt_ipv4(req->sipv4, ssipv4);
            fmt_ipv4(req->dipv4, sdipv4);
            printf("\t==> ARP Packet\n");
            printf("\t\t(%s) Who has %s, tell %s (%s)\n", fmt_arp_op(msg->op),
                   sdipv4, ssipv4, ssmac);
        }
        /*
         * IPv4
         */
        else if (ethhdr->ethertype == ETH_P_IP && eth_frame->child) {
            struct frame *ipv4_frame = eth_frame->child;
            struct ipv4_hdr *ipv4hdr = ipv4_hdr(ipv4_frame);

            char ip4_ssaddr[16], ip4_sdaddr[16];
            fmt_ipv4(ipv4hdr->saddr, ip4_ssaddr);
            fmt_ipv4(ipv4hdr->daddr, ip4_sdaddr);

            printf("\t==> IP Packet\n");
            printf("\t\tVersion:\t%u\n", ipv4hdr->version);
            printf("\t\tIHL:\t\t%u words\n", ipv4hdr->hdr_len);
            printf("\t\tLength:\t\t%u bytes\n", ipv4hdr->len);
            printf("\t\tTTL:\t\t%u\n", ipv4hdr->ttl);
            printf("\t\tProtocol:\t0x%02X > %s\n", ipv4hdr->proto,
                   fmt_ipproto(ipv4hdr->proto));
            printf("\t\tChecksum:\t%u\n", ipv4hdr->csum);
            printf("\t\tSource:\t\t%s\n", ip4_ssaddr);
            printf("\t\tDestination:\t%s\n", ip4_sdaddr);

            /*
             * TCP
             */
            if (ipv4hdr->proto == IP_P_TCP && ipv4_frame->child) {
                struct frame *tcp_frame = ipv4_frame->child;
                struct tcp_hdr *tcphdr = tcp_hdr(tcp_frame);
                int data_len = ipv4hdr->len - tcp_hdr_len(tcphdr)
                               - ipv4_hdr_len(ipv4hdr);
                char flags[10];
                fmt_tcp_flags(tcphdr, flags);

                printf("\t\t==> TCP Packet\n");
                printf("\t\t\tS-Port:\t%u\n", tcphdr->sport);
                printf("\t\t\tD-Port:\t%u\n", tcphdr->dport);
                // TODO: Check seq/ack numbers, they seem too big
                printf("\t\t\tSeq #:\t%u\n", tcphdr->seqn);
                printf("\t\t\tAck #:\t%u\n", tcphdr->ackn);
                printf("\t\t\tFlags:\t%s\n", flags);
                printf("\t\t\tLength:\t%d\n", data_len);
                printf("\t\t\tTCP HL:\t%d words\n", tcphdr->hdr_len);
                printf("\n");

                // Print xxd-style hex-dump of packet contents
                if (false) {
                    uint8_t *data = tcp_frame->data + tcp_hdr_len(tcphdr);
                    for (int i = 0; i < data_len; i += 16) {
                        printf("%08x: ", i);
                        for (int j = 0; j < 16; j += 2) {
                            printf("%02x%02x ", data[i + j], data[i + j + 1]);
                        }
                        for (char k = 0; k < 16; k++) {
                            if (isprint(data[i + k])) {
                                printf("%c", (data[i + k]));
                            } else {
                                printf(".");
                            }
                        }
                        printf("\n");
                    }
                }
            }
        }

        cleanup:
        free_frame(eth_frame);
    }

    intf->free(intf);
    free(intf);

    perror("recv error (MSG_PEEK|MSG_TRUNC)");

    return 0;
}
