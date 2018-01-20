#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <string.h>
#include <pthread.h>
#include <sysexits.h>

#include <sys/wait.h>
#include <sys/capability.h>

#include <netstack/log.h>
#include <netstack/ip/route.h>
#include <netstack/tcp/tcp.h>
#include <netstack/intf/rawsock.h>

// TODO: Add many configurable interfaces
// TODO: Add loopback interface
static struct intf *intf;

int main(int argc, char **argv) {

    // Initialise default logging with stdout & stderr
    log_default();
    logconf.lvlstr[LFRAME] = "PACKET";

    // Check for effective CAP_NET_RAW,CAP_NET_ADMIN capabilities
    cap_flag_value_t hasRaw = CAP_CLEAR,
            hasAdmin = CAP_CLEAR;
    cap_t capabilities = cap_get_proc();
    if (cap_get_flag(capabilities, CAP_NET_RAW, CAP_EFFECTIVE, &hasRaw) ||
        cap_get_flag(capabilities, CAP_NET_ADMIN, CAP_EFFECTIVE, &hasAdmin)) {
        LOG(LERR, "Error checking capabilities");
    }
    cap_free(capabilities);

    // Check and error if capabilities aren't set
    if (hasRaw != CAP_SET) {
        LOG(LCRIT, "You don't have the CAP_NET_RAW capability.\n"
                "Use 'setcap cap_net_raw+ep %s' or run as root", argv[0]);
        exit(1);
    } else if (hasAdmin != CAP_SET) {
        LOG(LCRIT, "You don't have the CAP_NET_ADMIN capability.\n"
                "Use 'setcap cap_net_admin+ep %s' or run as root", argv[0]);
        exit(1);
    }

    // TODO: Take different socket types into account here
    // e.g. TUN vs TAP, ignoring ETHER layer for example
    // TODO: For now, assume everything is ethernet

    // Create a INTF_RAWSOCK interface for sending/recv'ing data
    intf = calloc(sizeof(struct intf), 1);
    if (rawsock_new(intf) != 0) {
        LOG(LCRIT, "Could not create INTF_RAWSOCK");
        return EX_IOERR;
    }

    // Create interface send/recv threads
    intf_init(intf);

    // Initialise signal handling
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGHUP);
    sigaddset(&sigs, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigs, NULL) != 0) {
        perror("pthread_sigmask");
    }

    // Main thread captures signals, waiting for program termination
    int signum;
    while (sigwait(&sigs, &signum) == 0) {
        LOG(LINFO, "Caught signal: %s\n", strsignal(signum));

        switch (signum) {
            // Cleanup and exit, responsibly
            case SIGINT:
            case SIGHUP:
            case SIGQUIT:
                // Cleanup TCP states
                LOG(LNTCE, "Cleaning up %hu TCP sockets", tcp_sockets.length);
                llist_iter(&tcp_sockets, tcp_sock_cleanup);
                llist_clear(&tcp_sockets);

                LOG(LNTCE, "Cleaning up interface %s", intf->name);
                LOG(LNTCE, "Stopping threads");
                // Cleanup threads
                // Send all terminations first, before waiting
                for (int i = 0; i < INTF_THR_MAX; i++) {
                    if (intf->threads[i]) {
                        // pthread_cancel(id) will invoke cleanup procedures
                        pthread_cancel(intf->threads[i]);
                    }
                }
                // Wait for each thread to finish terminating
                for (int i = 0; i < INTF_THR_MAX; i++) {
                    if (intf->threads[i]) {
                        pthread_join(intf->threads[i], NULL);
                    }
                }

                // Cleanup route table
                llist_iter(&route_tbl, free);
                llist_clear(&route_tbl);

                // Cleanup interface meta
                intf->free(intf);
                free(intf);

                LOG(LWARN, "Exiting!");

                llist_iter(&logconf.streams, free);
                llist_clear(&logconf.streams);

                return EXIT_SUCCESS;
            default:
                // Do nothing, it doesn't concern us
                continue;
        }
    }
    perror("Signal error");
}
