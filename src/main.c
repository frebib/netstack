#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <string.h>
#include <pthread.h>
#include <sysexits.h>

#include <sys/wait.h>
#include <sys/capability.h>

#include <netstack/frame.h>
#include <netstack/frame.h>
#include <netstack/eth/ether.h>
#include <netstack/eth/ether.h>
#include <netstack/intf/rawsock.h>
#include <netstack/intf/rawsock.h>

// TODO: Add many configurable interfaces
// TODO: Add loopback interface
static struct intf *intf;

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

    // TODO: Take different socket types into account here
    // e.g. TUN vs TAP, ignoring ETHER layer for example
    // TODO: For now, assume everything is ethernet

    // Create a INTF_RAWSOCK interface for sending/recv'ing data
    intf = malloc(sizeof(struct intf));
    if (new_rawsock(intf) != 0) {
        perror("Error creating INTF_RAWSOCK");
        return EX_IOERR;
    }

    // Create interface send/recv threads
    init_intf(intf);

    // Initialise signal handling
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGHUP);
    sigaddset(&sigs, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigs, NULL) != 0) {
        perror("pthread_sigmask");
    }

    // Main thread captures signals, waiting for program termination
    while (true) {
        int signum;
        if (sigwait(&sigs, &signum) != 0) {
            perror("Signal error");
        }

        fprintf(stderr, "Caught signal: %s\n", strsignal(signum));

        switch (signum) {
            // Cleanup and exit, responsibly
            case SIGINT:
            case SIGHUP:
            case SIGQUIT:
                // Cleanup threads
                // Send all terminations first, before waiting
                for (int i = 0; i < INTF_THR_MAX; i++) {
                    if (intf->threads[i]) {
                        // pthread_cancel(id) will invoke cleanup procedures
                        // TODO: Use pthread_setcancelstate() appropriately
                        pthread_cancel(intf->threads[i]);
                    }
                }
                // Wait for each thread to finish terminating
                for (int i = 0; i < INTF_THR_MAX; i++) {
                    if (intf->threads[i]) {
                        pthread_join(intf->threads[i], NULL);
                    }
                }

                // Cleanup interface meta
                intf->free(intf);
                free(intf);

                fprintf(stderr, "Exiting!\n");
                return 0;
            default:
                // Do nothing, it doesn't concern us
                continue;
        }
    }
}
