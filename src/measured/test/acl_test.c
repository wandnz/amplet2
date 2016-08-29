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
#include <assert.h>
#include <string.h>
#include "acl.h"



/*
 *
 */
int main(void) {
    struct acl_root *root;

    root = initialise_acl();

    assert(root);

    /* check default permissions for all - deny */
    assert(get_acl(root, "all", ACL_NONE) == 0);
    assert(get_acl(root, "all", ACL_SERVER) == 0);
    assert(get_acl(root, "all", ACL_TEST) == 0);
    assert(get_acl(root, "all", ACL_SCHEDULE) == 0);
    assert(get_acl(root, "all", ACL_ALL) == 0);

    /* check default permissions for undefined host - deny */
    assert(get_acl(root, "undefined", ACL_NONE) == 0);
    assert(get_acl(root, "undefined", ACL_SERVER) == 0);
    assert(get_acl(root, "undefined", ACL_TEST) == 0);
    assert(get_acl(root, "undefined", ACL_SCHEDULE) == 0);
    assert(get_acl(root, "undefined", ACL_ALL) == 0);

    /* add allow permissions for a hostname and check that they are correct */
    add_acl(root, "foo.amp.wand.net.nz", ACL_SERVER, 1);
    add_acl(root, "bar.amp.wand.net.nz", ACL_TEST, 1);
    add_acl(root, "baz.amp.wand.net.nz", ACL_SCHEDULE, 1);

    assert(get_acl(root, "foo.amp.wand.net.nz", ACL_SERVER) == 1);
    assert(get_acl(root, "foo.amp.wand.net.nz", ACL_TEST) == 0);
    assert(get_acl(root, "foo.amp.wand.net.nz", ACL_SCHEDULE) == 0);

    assert(get_acl(root, "bar.amp.wand.net.nz", ACL_SERVER) == 0);
    assert(get_acl(root, "bar.amp.wand.net.nz", ACL_TEST) == 1);
    assert(get_acl(root, "bar.amp.wand.net.nz", ACL_SCHEDULE) == 0);

    assert(get_acl(root, "baz.amp.wand.net.nz", ACL_SERVER) == 0);
    assert(get_acl(root, "baz.amp.wand.net.nz", ACL_TEST) == 0);
    assert(get_acl(root, "baz.amp.wand.net.nz", ACL_SCHEDULE) == 1);

    /* make sure partial matches don't get the permissions */
    assert(get_acl(root, "amp.wand.net.nz", ACL_SERVER) == 0);
    assert(get_acl(root, "wand.net.nz", ACL_SERVER) == 0);
    assert(get_acl(root, "net.nz", ACL_SERVER) == 0);
    assert(get_acl(root, "nz", ACL_SERVER) == 0);

    /* add a partial match rule to make sure that they do get permissions */
    add_acl(root, ".wand.net.nz", ACL_TEST, 1);

    assert(get_acl(root, "foo.amp.wand.net.nz", ACL_TEST) == 1);
    assert(get_acl(root, "amp.wand.net.nz", ACL_TEST) == 1);
    assert(get_acl(root, "wand.net.nz", ACL_TEST) == 0);
    assert(get_acl(root, "net.nz", ACL_TEST) == 0);
    assert(get_acl(root, "nz", ACL_TEST) == 0);

    /* add an allow all rule and check that non-explicitly set hosts match it */
    add_acl(root, "all", ACL_SCHEDULE, 1);

    assert(get_acl(root, "foo.amp.wand.net.nz", ACL_SCHEDULE) == 1);
    assert(get_acl(root, "amp.wand.net.nz", ACL_SCHEDULE) == 1);
    assert(get_acl(root, "wand.net.nz", ACL_SCHEDULE) == 1);
    assert(get_acl(root, "net.nz", ACL_SCHEDULE) == 1);
    assert(get_acl(root, "nz", ACL_SCHEDULE) == 1);

    /* add some deny rules to make sure they override the allow all */
    add_acl(root, "foo.amp.wand.net.nz", ACL_SCHEDULE, 0);

    assert(get_acl(root, "foo.amp.wand.net.nz", ACL_SCHEDULE) == 0);
    assert(get_acl(root, "amp.wand.net.nz", ACL_SCHEDULE) == 1);
    assert(get_acl(root, "wand.net.nz", ACL_SCHEDULE) == 1);
    assert(get_acl(root, "net.nz", ACL_SCHEDULE) == 1);
    assert(get_acl(root, "nz", ACL_SCHEDULE) == 1);

    /* add a partial match rule to deny the permissions again */
    add_acl(root, ".wand.net.nz", ACL_SCHEDULE, 0);

    assert(get_acl(root, "foo.amp.wand.net.nz", ACL_SCHEDULE) == 0);
    assert(get_acl(root, "amp.wand.net.nz", ACL_SCHEDULE) == 0);
    assert(get_acl(root, "wand.net.nz", ACL_SCHEDULE) == 1);
    assert(get_acl(root, "net.nz", ACL_SCHEDULE) == 1);
    assert(get_acl(root, "nz", ACL_SCHEDULE) == 1);

    /* restart with a fresh ACL to check overlapping wildcards */
    free_acl(root);
    root = initialise_acl();

    /* grant a specific host permissions */
    add_acl(root, "foo.bar.baz.wand.net.nz", ACL_TEST, 1);
    assert(get_acl(root, "foo.bar.baz.wand.net.nz", ACL_TEST) == 1);
    assert(get_acl(root, "bar.baz.wand.net.nz", ACL_TEST) == 0);
    assert(get_acl(root, "baz.wand.net.nz", ACL_TEST) == 0);

    /* then add a wildcard a few sections further up with allow permissions*/
    add_acl(root, ".wand.net.nz", ACL_TEST, 1);
    assert(get_acl(root, "foo.bar.baz.wand.net.nz", ACL_TEST) == 1);
    assert(get_acl(root, "bar.baz.wand.net.nz", ACL_TEST) == 1);
    assert(get_acl(root, "baz.wand.net.nz", ACL_TEST) == 1);

    /* and another wildcard even further up again with deny permissions */
    add_acl(root, ".nz", ACL_TEST, 0);
    assert(get_acl(root, "foo.bar.baz.wand.net.nz", ACL_TEST) == 1);
    assert(get_acl(root, "bar.baz.wand.net.nz", ACL_TEST) == 1);
    assert(get_acl(root, "baz.wand.net.nz", ACL_TEST) == 1);
    assert(get_acl(root, "foo.net.nz", ACL_TEST) == 0);
    assert(get_acl(root, "foo.bar.net.nz", ACL_TEST) == 0);
    assert(get_acl(root, "foo.bar.baz.net.nz", ACL_TEST) == 0);
    assert(get_acl(root, "foo.nz", ACL_TEST) == 0);

    free_acl(root);

    return 0;
}
