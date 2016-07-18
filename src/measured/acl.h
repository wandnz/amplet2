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
