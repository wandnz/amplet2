#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "tests.h"
#include "traceroute.h"

/*
 * Check that the traceroute test registration is vaguely sane.
 */
int main(void) {
    test_t *info = register_test();

    assert(info != NULL);

    assert(info->id == AMP_TEST_TRACEROUTE);
    assert(strcmp(info->name, "traceroute") == 0);
    assert(info->run_callback != NULL);
    assert(info->print_callback != NULL);
    assert(info->max_duration > 0);

    return 0;
}
