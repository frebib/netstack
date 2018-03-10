#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <string.h>
#include <pthread.h>

#include <sys/wait.h>

#define NETSTACK_LOG_UNIT "NETD"
#include <netstack.h>
#include <netstack/log.h>
#include <netstack/inet/route.h>
#include <netstack/tcp/tcp.h>
#include <netstack/intf/rawsock.h>

// TODO: Add many configurable interfaces
// TODO: Add loopback interface
static struct intf *intf;


int main(int argc, char **argv) {

    // Initialise default config & netstack internals
    netstack_init();

    // Check for effective CAP_NET_RAW,CAP_NET_ADMIN capabilities
    if (netstack_checkcap(argv[0]))
        exit(EXIT_FAILURE);

    // TODO: Take interface etc. configuration from config file

    // Create a INTF_RAWSOCK interface for sending/recv'ing data
    intf = calloc(sizeof(struct intf), 1);
    if (rawsock_new(intf) != 0) {
        LOG(LCRIT, "Could not create INTF_RAWSOCK");
        exit(EXIT_FAILURE);
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
        LOG(LINFO, "Caught signal: %s", strsignal(signum));

        switch (signum) {
            // Cleanup and exit, responsibly
            case SIGINT:
            case SIGHUP:
            case SIGQUIT:
                // Cleanup TCP states
                LOG(LNTCE, "Cleaning up %zu TCP sockets", tcp_sockets.length);
                llist_iter(&tcp_sockets, tcp_sock_cleanup);
                llist_clear(&tcp_sockets);

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
                LOG(LNTCE, "Cleaning up interface %s", intf->name);
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
