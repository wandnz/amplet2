#include <stdio.h>

#include "usage.h"
#include "config.h"



/*
 * Print the package version string.
 */
void print_package_version(char *prog) {
    fprintf(stderr, "%s, version %s\n", prog, PACKAGE_STRING);
}



/*
 * Print the test options relating to tests using individual probe packets
 * (as opposed to TCP streams for example).
 */
void print_probe_usage(void) {
    fprintf(stderr, "  -Q, --dscp           <code>    "
                "IP differentiated services codepoint to set\n");
    fprintf(stderr, "  -Z, --interpacketgap <usec>    "
            "Minimum number of microseconds between packets\n");
}



/*
 * Print the test options relating to setting source interface and source
 * addresses.
 */
void print_interface_usage(void) {
    fprintf(stderr, "  -I, --interface      <iface>   Source interface name\n");
    fprintf(stderr, "  -4, --ipv4           <address> Source IPv4 address\n");
    fprintf(stderr, "  -6, --ipv6           <address> Source IPv6 address\n");
}



/*
 * Print the generic test options that are common to every test.
 */
void print_generic_usage(void) {
    fprintf(stderr, "  -h, --help                     "
                "Print help information and exit\n");
    fprintf(stderr, "  -v, --version                  "
            "Print version information and exit\n");
    fprintf(stderr, "  -x, --debug                    Enable debug output\n");
}
