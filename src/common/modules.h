#ifndef _COMMON_MODULES_H
#define _COMMON_MODULES_H

#include "tests.h"

/* Array containing pointers to all the available tests. */
test_t *amp_tests[AMP_TEST_LAST];


int register_tests(char *location);
void unregister_tests(void);

#endif
