#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "tests.h"
#include "icmp.h"

/*
 * Check that the icmp test registration is vaguely sane.
 */
int main(int argc, char *argv[]) {
    test_t *info = register_test();

    assert(info != NULL);

    assert(info->id == AMP_TEST_ICMP);
    assert(strcmp(info->name, "icmp") == 0);
    assert(info->run_callback != NULL);
    assert(info->print_callback != NULL);
    assert(info->max_duration > 0);

    return 0;
}
