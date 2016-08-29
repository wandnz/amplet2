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

#ifndef _MEASURED_ACL_H
#define _MEASURED_ACL_H

#include <stdint.h>

#define ACL_NONE 0x00
#define ACL_SERVER 0x01
#define ACL_TEST 0x02
#define ACL_SCHEDULE 0x04
#define ACL_ALL (ACL_SERVER | ACL_TEST | ACL_SCHEDULE)

struct acl_node {
    char *label;
    uint8_t permissions;
    uint8_t isset;
    uint8_t num_children;
    struct acl_node **children;
};

struct acl_root {
    struct acl_node *server;
    struct acl_node *test;
    struct acl_node *schedule;
};

struct acl_root* initialise_acl(void);
void free_acl(struct acl_root *root);
void print_acl(struct acl_root *root);
uint8_t get_acl(struct acl_root *root, char *fqdn, uint8_t property);
int add_acl(struct acl_root *root, char *fqdn, uint8_t property, uint8_t value);
#endif
