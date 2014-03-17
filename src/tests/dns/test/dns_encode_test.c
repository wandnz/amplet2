#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "tests.h"
#include "dns.h"

/*
 * Check that encoding names gives the correct results. Names should be encoded
 * according to section 4.1.4 of http://www.ietf.org/rfc/rfc1035.txt.
 *
 * All of these should simply be encoded by replacing the dots in the name
 * with a length byte decribing the length of the following element. We don't
 * bother doing any compression when we encode, as there is only ever a single
 * name in the request.
 */
int main(void) {
    int i;
    int count;
    char *encoded;

    /* try some pretty basic examples, varying number of elements */
    char *queries[] = {
        "www.example.org",
        "foo.bar.baz.example.org",
        "a.bb.ccc.dddd.example.org",
        "www.wand.net.nz",
        "skeptic.wand.net.nz",
        "waikato.amp.wand.net.nz",
        "abcdefghijklmnopqrstuvwxyz.example.org",
    };

    /* known correct encodings for the above names */
    char *responses[] = {
        "\x03www\x07""example\x03org",
        "\x03""foo\x03""bar\x03""baz\x07""example\x03org",
        "\x01""a\x02""bb\x03""ccc\04""dddd\x07""example\x03org",
        "\x03www\x04wand\x03net\x02nz",
        "\x07skeptic\x04wand\x03net\x02nz",
        "\x07waikato\x03""amp\x04wand\x03net\x02nz",
        "\x1a""abcdefghijklmnopqrstuvwxyz\x07""example\x03org",
    };

    assert(sizeof(queries) == sizeof(responses));

    /* encode the name and make sure it matches what we expect */
    count = sizeof(queries) / sizeof(char*);
    for ( i = 0; i < count; i++ ) {
        encoded = amp_test_dns_encode(queries[i]);
        assert(strcmp(encoded, responses[i]) == 0);
        free(encoded);
    }

    return 0;
}
