/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Brendon Jones
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * amplet2 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations including
 * the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 *
 * amplet2 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with amplet2. If not, see <http://www.gnu.org/licenses/>.
 */

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
    fprintf(stderr, "  -Z, --interpacketgap <usec>    "
            "Minimum number of microseconds between packets\n");
}



/*
 * Print the test options relating to setting source interface and source
 * addresses.
 */
void print_interface_usage(void) {
    fprintf(stderr, "  -Q, --dscp           <code>    "
                "IP differentiated services codepoint to set\n");
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
