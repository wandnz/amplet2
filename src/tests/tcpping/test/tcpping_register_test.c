#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "tests.h"
#include "tcpping.h"

/*
 * Check that the tcpping test registration is vaguely sane.
 */
int main(void) {
    test_t *info = register_test();

    assert(info != NULL);

    assert(info->id == AMP_TEST_TCPPING);
    assert(strcmp(info->name, "tcpping") == 0);
    assert(info->run_callback != NULL);
    assert(info->print_callback != NULL);
    assert(info->max_duration > 0);

    free(info->name);
    free(info);

    return 0;
}
