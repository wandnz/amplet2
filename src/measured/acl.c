#include <config.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

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
    label = rindex(fqdn, '.');

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
static struct acl_node* new_acl_node(char *label, uint8_t permissions) {
    struct acl_node *acl;

    assert(label);

    acl = calloc(1, sizeof(struct acl_node));
    acl->label = strdup(label);
    acl->permissions = permissions;
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
    root->server = new_acl_node("all", ACL_NONE);
    root->test = new_acl_node("all", ACL_NONE);
    root->schedule = new_acl_node("all", ACL_NONE);

    return root;
}



/*
 *
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
 *
 */
uint8_t get_acl(struct acl_root *root, char *fqdn, uint8_t property) {
    struct acl_node *subtree = NULL;
    char *label;
    uint8_t value;

    assert(root);
    assert(fqdn);

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
 *
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
                /* this is the end node we wanted - modify it */
                root->children[i]->permissions = value;
            }

            return root;
        }
    }

    /* the label is new, add it to the tree and keep going */
    root->children = realloc(root->children,
            (sizeof(struct acl_node*)) * (root->num_children+1));

    if ( label == fqdn ) {
        /* leaf node, set the permissions as given by the user */
        root->children[root->num_children++] = new_acl_node(label, value);
    } else {
        /* internal node, set the same permissions as the parent */
        struct acl_node *child = new_acl_node(label, root->permissions);
        label[0] = '\0';
        root->children[root->num_children++] =
            add_acl_internal(child, fqdn, value);
    }

    return root;
}



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

    /* "all" is a special node at the start of the tree others inherit from */
    if ( strcmp(fqdn, "all") == 0 ) {
        subtree->permissions = value;
    } else {
        char *label = strdup(fqdn);
        add_acl_internal(subtree, label, value);
        free(label);
    }

    return 0;
}



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
 *
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



void free_acl(struct acl_root *root) {
    if ( root == NULL ) {
        return;
    }

    free_acl_internal(root->server);
    free_acl_internal(root->test);
    free_acl_internal(root->schedule);
    free(root);
}
