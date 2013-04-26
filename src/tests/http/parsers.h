#ifndef _TESTS_HTTP_PARSERS_H
#define _TESTS_HTTP_PARSERS_H

#include <stdlib.h>

size_t do_nothing(__attribute__((unused))void *ptr, size_t size,
        size_t nmemb, __attribute__((unused))void *data);
size_t parse_headers(void *ptr, size_t size, size_t nmemb, void *data);
size_t parse_response(void *ptr, size_t size, size_t nmemb, void *data);

#endif
