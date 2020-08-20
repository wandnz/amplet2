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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "debug.h"
#include "acl.h"



/*
 * Get the last portion of the domain name, from the last dot to the end of
 * the string. If there is no dot then return the whole string.
 */
static char* get_label(char *fqdn) {
    char *label;

    assert(fqdn);

    /* take the last label in the fqdn, we build the tree in reverse */
    label = strrchr(fqdn, '.');

    if ( label == NULL ) {
        /* no dot, must be the last element so the label is the whole fqdn */
        label = fqdn;
    }

    return label;
}



/*
 * Create and return a new ACL node with the given permissions. Any permissions
 * not specified will default to "deny".
 */
static struct acl_node* new_acl_node(char *label, uint8_t permissions,
        uint8_t isset) {
    struct acl_node *acl;

    assert(label);

    acl = calloc(1, sizeof(struct acl_node));
    acl->label = strdup(label);
    acl->permissions = permissions;
    acl->isset = isset;
    acl->num_children = 0;
    acl->children = NULL;

    return acl;
}



/*
 * Initialise and return a new ACL with a default deny all rule. The ACL is
 * actually represented by 3 trees, one for each permission, rooted at the
 * special node "all".
 */
struct acl_root* initialise_acl(void) {
    struct acl_root *root;

    root = calloc(1, sizeof(struct acl_root));
    root->server = new_acl_node("all", ACL_NONE, 0);
    root->test = new_acl_node("all", ACL_NONE, 0);
    root->schedule = new_acl_node("all", ACL_NONE, 0);

    return root;
}



/*
 * Internal recursive function to find an ACL label, or the closest parent.
 */
static uint8_t get_acl_internal(struct acl_node *root, char *fqdn) {
    assert(root);

    /* check if there are children containing more specific rules */
    if ( root->num_children > 0 ) {
        char *label;
        int i;

        label = get_label(fqdn);

        /* check if a child of the current node matches - more specific rule */
        for ( i = 0; i < root->num_children; i++ ) {
            if ( strcmp(root->children[i]->label, label) == 0 ) {
                /* chop off the label from the end of the fqdn */
                label[0] = '\0';
                return get_acl_internal(root->children[i], fqdn);
            }
        }
    }

    /* no matching children, so use the permissions from this node */
    return root->permissions;
}



/*
 * Find and return the permissions for the given FQDN and property.
 */
uint8_t get_acl(struct acl_root *root, char *fqdn, uint8_t property) {
    struct acl_node *subtree = NULL;
    char *label;
    uint8_t value;

    if ( root == NULL || fqdn == NULL ) {
        return 0;
    }

    switch ( property ) {
        case ACL_SERVER: subtree = root->server; break;
        case ACL_TEST: subtree = root->test; break;
        case ACL_SCHEDULE: subtree = root->schedule; break;
        default: return 0;
    };

    label = strdup(fqdn);
    value = get_acl_internal(subtree, label);
    free(label);

    return value;
}



/*
 * Set the permissions on every element in the tree that hasn't already been
 * explicitly set.
 */
static void update_acl_subtree(struct acl_node *root, uint8_t value) {
    int i;

    assert(root);

    /* if the node is a more specific wildcard then don't update the subtree */
    if ( root->isset && root->label[0] == '.' ) {
        return;
    }

    /*
     * Only update the permissions if they weren't explicitly set - we want
     * more specific rules to override the wildcard we are setting.
     */
    if ( !root->isset ) {
        root->permissions = value;
    }

    /* update all the children */
    for ( i = 0; i < root->num_children; i++ ) {
        update_acl_subtree(root->children[i], value);
    }
}



/*
 * Internal recursive function to add a rule to the ACL.
 */
static struct acl_node* add_acl_internal(struct acl_node *root, char *fqdn,
        uint8_t value) {
    char *label;
    int i;

    /* if the acl was initialised, we will have at least an "all" node */
    assert(root);

    label = get_label(fqdn);

    /* check if this name is already in the list of children */
    for ( i = 0; i < root->num_children; i++ ) {
        if ( strcmp(root->children[i]->label, label) == 0 ) {
            if ( label != fqdn ) {
                /* on the right track, keep traversing looking for the node */
                label[0] = '\0';
                root->children[i] =
                    add_acl_internal(root->children[i], fqdn, value);
            } else {
                int j;

                /* this is the end node we wanted - modify it */
                root->children[i]->permissions = value;
                root->children[i]->isset = 1;

                if ( label[0] == '.' ) {
                    /* if it's a wildcard then update the subtree as well */
                    for ( j = 0; j < root->children[i]->num_children; j++ ) {
                        update_acl_subtree(root->children[i]->children[j],
                                value);
                    }
                }
            }

            return root;
        }
    }

    /* the label is new, add it to the tree and keep going */
    root->children = realloc(root->children,
            (sizeof(struct acl_node*)) * (root->num_children+1));

    if ( label == fqdn ) {
        /* leaf node, set the permissions as given by the user */
        root->children[root->num_children++] = new_acl_node(label, value, 1);
    } else {
        /* internal node, set the same permissions as the parent */
        struct acl_node *child = new_acl_node(label, root->permissions, 0);
        label[0] = '\0';
        root->children[root->num_children++] =
            add_acl_internal(child, fqdn, value);
    }

    return root;
}



/*
 * Add a rule to the ACL.
 */
int add_acl(struct acl_root *root, char *fqdn, uint8_t property, uint8_t value) {
    struct acl_node *subtree = NULL;

    assert(root);
    assert(fqdn);

    switch ( property ) {
        case ACL_SERVER: subtree = root->server; break;
        case ACL_TEST: subtree = root->test; break;
        case ACL_SCHEDULE: subtree = root->schedule; break;
        default: return -1;
    };

    assert(subtree);

    /*
     * "all" is a special node at the start of the tree others inherit from,
     * if there are changes to this then they also need to propagate through
     * the rest of the tree.
     */
    if ( strcmp(fqdn, "all") == 0 ) {
        update_acl_subtree(subtree, value);
    } else {
        char *label = strdup(fqdn);
        add_acl_internal(subtree, label, value);
        free(label);
    }

    return 0;
}



/*
 * Traverse an ACL tree and print the contents.
 */
static void print_acl_internal(struct acl_node *root) {
    int i;

    assert(root);

    Log(LOG_INFO, "%s %d", root->label, root->permissions);
    for ( i = 0; i < root->num_children; i++ ) {
        Log(LOG_INFO, " %s", root->children[i]->label);
    }
    Log(LOG_INFO, "\n");

    for ( i = 0; i < root->num_children; i++ ) {
        print_acl_internal(root->children[i]);
    }

}



/*
 * Print all three ACL trees used for server, test and schedule permissions.
 */
void print_acl(struct acl_root *root) {
    if ( root == NULL ) {
        return;
    }

    Log(LOG_INFO, "SERVER:");
    print_acl_internal(root->server);

    Log(LOG_INFO, "TEST:");
    print_acl_internal(root->test);

    Log(LOG_INFO, "SCHEDULE:");
    print_acl_internal(root->schedule);
}



/*
 * Traverse an ACL tree and free the contents.
 */
static void free_acl_internal(struct acl_node *root) {
    int i;

    assert(root);

    for ( i = 0; i < root->num_children; i++ ) {
        free_acl_internal(root->children[i]);
    }

    free(root->label);
    free(root->children);
    free(root);
}



/*
 * Free all three ACL trees used for server, test and schedule permissions.
 */
void free_acl(struct acl_root *root) {
    if ( root == NULL ) {
        return;
    }

    free_acl_internal(root->server);
    free_acl_internal(root->test);
    free_acl_internal(root->schedule);
    free(root);
}
