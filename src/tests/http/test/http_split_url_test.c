#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "tests.h"
#include "http.h"


struct expected {
    char *url;
    char *host;
    char *path;
    /* TODO check set works properly? */
};


/*
 * Check that the http test is correctly parsing URL strings.
 */
int main(void) {
    int count, i;
    char host[MAX_DNS_NAME_LEN];
    char path[MAX_PATH_LEN];
    struct expected data[] = {
        /* first fetch is special and will assume http if no scheme given */
        {"www.wand.net.nz/foo/bar/baz.html",
            "http://www.wand.net.nz", "/foo/bar/baz.html"},

        /* check http urls, single path element */
        {"http://www.wand.net.nz", "http://www.wand.net.nz", "/"},
        {"http://www.wand.net.nz/", "http://www.wand.net.nz", "/"},
        {"http://wand.net.nz/baz.html", "http://wand.net.nz", "/baz.html"},
        {"//www.wand.net.nz", "http://www.wand.net.nz", "/"},
        {"//www.wand.net.nz/", "http://www.wand.net.nz", "/"},
        {"//www.wand.net.nz/baz.png", "http://www.wand.net.nz", "/baz.png"},
        {"/", "http://www.wand.net.nz", "/"},
        {"/baz.css", "http://www.wand.net.nz", "/baz.css"},
        {"baz.mp4", "http://www.wand.net.nz", "/baz.mp4"},

        /* check http urls, two path elements */
        {"http://www.example.org/foo", "http://www.example.org", "/foo"},
        {"http://www.example.org/foo/", "http://www.example.org", "/foo/"},
        {"http://example.org/foo/baz.js", "http://example.org", "/foo/baz.js"},
        {"//www.example.org/foo", "http://www.example.org", "/foo"},
        {"//www.example.org/foo/", "http://www.example.org", "/foo/"},
        {"//example.org/foo/baz.gif", "http://example.org", "/foo/baz.gif"},
        {"/", "http://example.org", "/"},
        {"/foo/baz.css", "http://example.org", "/foo/baz.css"},
        {"baz.wav", "http://example.org", "/foo/baz.wav"},

        /* check http urls, three path elements */
        {"http://amp.wand.net.nz/foo/bar",
            "http://amp.wand.net.nz", "/foo/bar"},
        {"http://amp.wand.net.nz/foo/bar/",
            "http://amp.wand.net.nz", "/foo/bar/"},
        {"http://amp.wand.net.nz/foo/bar/baz.php",
            "http://amp.wand.net.nz", "/foo/bar/baz.php"},
        {"//amp.wand.net.nz/foo/bar", "http://amp.wand.net.nz", "/foo/bar"},
        {"//amp.wand.net.nz/foo/bar/", "http://amp.wand.net.nz", "/foo/bar/"},
        {"//amp.wand.net.nz/foo/bar/baz.asp",
            "http://amp.wand.net.nz", "/foo/bar/baz.asp"},
        {"/", "http://amp.wand.net.nz", "/"},
        {"/foo/bar/baz.css", "http://amp.wand.net.nz", "/foo/bar/baz.css"},
        {"baz.abcdefgh", "http://amp.wand.net.nz", "/foo/bar/baz.abcdefgh"},


        /* check https urls, single path element */
        {"https://www.wand.net.nz", "https://www.wand.net.nz", "/"},
        {"https://www.wand.net.nz/", "https://www.wand.net.nz", "/"},
        {"https://wand.net.nz/baz.html", "https://wand.net.nz", "/baz.html"},
        {"//www.wand.net.nz", "https://www.wand.net.nz", "/"},
        {"//www.wand.net.nz/", "https://www.wand.net.nz", "/"},
        {"//wand.net.nz/baz.png", "https://wand.net.nz", "/baz.png"},
        {"/", "https://wand.net.nz", "/"},
        {"/baz.css", "https://wand.net.nz", "/baz.css"},
        {"baz.mp4", "https://wand.net.nz", "/baz.mp4"},

        /* check https urls, two path elements */
        {"https://www.example.org/foo", "https://www.example.org", "/foo"},
        {"https://www.example.org/foo/", "https://www.example.org", "/foo/"},
        {"https://example.org/foo/baz.js", "https://example.org","/foo/baz.js"},
        {"//www.example.org/foo", "https://www.example.org", "/foo"},
        {"//www.example.org/foo/", "https://www.example.org", "/foo/"},
        {"//example.org/foo/baz.gif", "https://example.org", "/foo/baz.gif"},
        {"/", "https://example.org", "/"},
        {"/foo/baz.css", "https://example.org", "/foo/baz.css"},
        {"baz.wav", "https://example.org", "/foo/baz.wav"},

        /* check https urls, three path elements */
        {"https://amp.wand.net.nz/foo/bar",
            "https://amp.wand.net.nz", "/foo/bar"},
        {"https://amp.wand.net.nz/foo/bar/",
            "https://amp.wand.net.nz", "/foo/bar/"},
        {"https://amp.wand.net.nz/foo/bar/baz.php",
            "https://amp.wand.net.nz", "/foo/bar/baz.php"},
        {"//amp.wand.net.nz/foo/bar", "https://amp.wand.net.nz", "/foo/bar"},
        {"//amp.wand.net.nz/foo/bar/", "https://amp.wand.net.nz", "/foo/bar/"},
        {"//amp.wand.net.nz/foo/bar/baz.asp",
            "https://amp.wand.net.nz", "/foo/bar/baz.asp"},
        {"/", "https://amp.wand.net.nz", "/"},
        {"/foo/bar/baz.css", "https://amp.wand.net.nz", "/foo/bar/baz.css"},
        {"baz.abcdefgh", "https://amp.wand.net.nz", "/foo/bar/baz.abcdefgh"},
    };

    count = sizeof(data) / sizeof(struct expected);

    for ( i = 0; i < count; i++ ) {
        amp_test_http_split_url(data[i].url, host, path, 1);
        assert(strcmp(host, data[i].host) == 0);
        assert(strcmp(path, data[i].path) == 0);
    }

    return 0;
}
