#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "tests.h"
#include "dns.h"

/*
 * Check that decoding names gives the correct results. Names should be decoded
 * according to section 4.1.4 of http://www.ietf.org/rfc/rfc1035.txt.
 */
int main(void) {
    int i;
    int count;
    char *name;

    /*
     * Some basic examples of encoded names, some without compression and
     * others having varying levels of redirection.
     */
    char *queries[] = {
        "\x03www\x07""example\x03org",
        "\x03""foo\x03""bar\x03""baz\x07""example\x03org",
        "\x01""a\x02""bb\x03""ccc\04""dddd\x07""example\x03org",
        "\x03www\x04wand\x03net\x02nz",
        "\x07skeptic\x04wand\x03net\x02nz",
        "\x07waikato\x03""amp\x04wand\x03net\x02nz",
        "\x1a""abcdefghijklmnopqrstuvwxyz\x07""example\x03org",
        "\x03www\x07""example\x03org\x00\03foo\xc0\x04\x00",
        "\x03www\x07""example\x03org\x00\03""bar\xc0\x04\x00\x03""foo\xc0\x11",
    };

    /* known correct decodings for the above names */
    char *responses[] = {
        "www.example.org",
        "foo.bar.baz.example.org",
        "a.bb.ccc.dddd.example.org",
        "www.wand.net.nz",
        "skeptic.wand.net.nz",
        "waikato.amp.wand.net.nz",
        "abcdefghijklmnopqrstuvwxyz.example.org",
        "foo.example.org",
        "foo.bar.example.org",
    };

    /* if compression is used, offset to the start of the name we want */
    int offsets[] = { 0, 0, 0, 0, 0, 0, 0, 17, 24};

    name = malloc(MAX_DNS_NAME_LEN * sizeof(char));
    memset(name, 0, MAX_DNS_NAME_LEN * sizeof(char));

    assert(sizeof(queries) == sizeof(responses));
    assert(sizeof(queries) / sizeof(char*) == sizeof(offsets) / sizeof(int));

    count = sizeof(queries) / sizeof(char*);
    for ( i = 0; i < count; i++ ) {
        amp_test_dns_decode(name, queries[i], queries[i] + offsets[i]);
        assert(strcmp(name, responses[i]) == 0);
    }

    free(name);

    return 0;
}
