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
