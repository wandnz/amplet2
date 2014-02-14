#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "nametable.h"


static size_t get_addr_len(int family) {
    int len;
    switch(family) {
        case AF_INET: len = sizeof(struct sockaddr_in); break;
        case AF_INET6: len = sizeof(struct sockaddr_in6); break;
        default: assert(0); break;
    };
    return len;
}

static void check_name_response(nametable_t *name_item, char *name, int count,
        struct addrinfo *addr1, struct addrinfo *addr2) {

    struct addrinfo *tmpaddr;
    struct addrinfo *required;

    /* check parts of the nametable_t response */
    assert(name_item);
    assert(count == 1 || count == 2);
    assert(name_item->count == count);
    assert(name_item->addr);

    /* check the contents of the addrinfo struct */
    tmpaddr = name_item->addr;
    assert(tmpaddr->ai_addr);
    assert(tmpaddr->ai_canonname);
    assert(strcmp(tmpaddr->ai_canonname, name) == 0);

    /* check that the address we get matches what we expected to see */
    if ( count == 1 ) {
        assert(tmpaddr->ai_family == addr1->ai_family);
        assert(memcmp(tmpaddr->ai_addr, addr1->ai_addr,
                    get_addr_len(tmpaddr->ai_family)) == 0);
    } else {
        assert(tmpaddr->ai_family == addr1->ai_family ||
                tmpaddr->ai_family == addr2->ai_family);

        /*
         * make sure that we get one of the addresses we put in for this name
         * and then determine which address we are still to get
         */
        if ( tmpaddr->ai_family == addr1->ai_family ) {
            assert(tmpaddr->ai_family == addr1->ai_family);
            assert(memcmp(tmpaddr->ai_addr, addr1->ai_addr,
                        get_addr_len(tmpaddr->ai_family)) == 0);
            required = addr2;
        } else if ( tmpaddr->ai_family == addr2->ai_family ) {
            assert(tmpaddr->ai_family == addr2->ai_family);
            assert(memcmp(tmpaddr->ai_addr, addr2->ai_addr,
                        get_addr_len(tmpaddr->ai_family)) == 0);
            required = addr1;
        } else {
            assert(0);
        }

        /* then make sure that we get the other address following it */
        tmpaddr = tmpaddr->ai_next;
        assert(tmpaddr->ai_addr);
        assert(tmpaddr->ai_next == NULL);
        assert(tmpaddr->ai_family == required->ai_family);
        assert(memcmp(tmpaddr->ai_addr, required->ai_addr,
                    get_addr_len(tmpaddr->ai_family)) == 0);
    }
}

static struct addrinfo *get_addr(char *address) {
    struct addrinfo *addrinfo;
    struct addrinfo hint;
    int res;

    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_flags = AI_NUMERICHOST;
    hint.ai_family = PF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM; /* limit it to a single socket type */
    hint.ai_protocol = 0;
    hint.ai_addrlen = 0;
    hint.ai_addr = NULL;
    hint.ai_canonname = NULL;
    hint.ai_next = NULL;
    addrinfo = NULL;

    res = getaddrinfo(address, NULL, &hint, &addrinfo);
    assert(res == 0);

    return addrinfo;
}


/*
 *
 */
int main(void) {
    extern nametable_t *name_table;
    struct addrinfo *addr1, *addr2, *addr3;
    char *name1 = "test.target.name1";
    char *name2 = "test.target.name2";
    nametable_t *name_item;

    addr1 = get_addr("130.217.250.13");
    addr2 = get_addr("2001:df0:4:4000:230:48ff:fe7f:5544");
    addr3 = get_addr("8.8.8.8");

    /* nametable is defined in nametable.c and should start empty */
    assert(name_table == NULL);

    /* clearing an empty nametable should result in an empty nametable */
    clear_nametable();
    assert(name_table == NULL);

    /* check that if we insert a name, it appears in the list */
    nametable_test_insert_nametable_entry(name1, addr1);
    assert(name_table != NULL);
    name_item = name_to_address(name1);
    check_name_response(name_item, name1, 1, addr1, NULL);

    /*
     * Add another entry with the same name and a different address, checking
     * that both addresses are returned for that name
     */
    nametable_test_insert_nametable_entry(name1, addr2);
    name_item = name_to_address(name1);
    check_name_response(name_item, name1, 2, addr1, addr2);

    /* add another name and make sure that we can fetch the new name...*/
    nametable_test_insert_nametable_entry(name2, addr3);
    name_item = name_to_address(name2);
    check_name_response(name_item, name2, 1, addr3, NULL);

    /* ...as well as the old name that was already in there */
    name_item = name_to_address(name1);
    check_name_response(name_item, name1, 2, addr1, addr2);

    /* clearing the nametable should result in an empty nametable */
    clear_nametable();
    assert(name_table == NULL);

    return 0;
}
