#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "tests.h"
#include "dns.h"

/*
 * Check that the dns test registration is vaguely sane.
 */
int main(void) {
    test_t *info = register_test();

    assert(info != NULL);

    assert(info->id == AMP_TEST_DNS);
    assert(strcmp(info->name, "dns") == 0);
    assert(info->run_callback != NULL);
    assert(info->print_callback != NULL);
    assert(info->server_callback == NULL);
    assert(info->max_duration > 0);

    free(info->name);
    free(info);

    return 0;
}
