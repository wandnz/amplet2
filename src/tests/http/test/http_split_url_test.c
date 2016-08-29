/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Brendon Jones
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * amplet2 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations including
 * the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 *
 * amplet2 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with amplet2. If not, see <http://www.gnu.org/licenses/>.
 */

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
