/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
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
#include <wordexp.h>
#include "schedule.h"



/*
 * Use the output of wordexp() as the ground truth for how the parser should
 * split arguments. wordexp() does everything we want, but isn't used because
 * it also expands variables and paths (which we don't want).
 */
static char **get_expected(char *text) {
    wordexp_t p;

    if ( wordexp(text, &p, 0) != 0 ) {
        return NULL;
    }

    return p.we_wordv;
}



/*
 * Parse the arguments using parse_param_string and make sure it matches the
 * expected result.
 */
static int check_parse(char *text) {
    char **actual;
    char **expected;
    char **a, **b;
    int result = 1;

    actual = parse_param_string(text);
    expected = get_expected(text);

    /* an invalid string should return NULL (e.g. mismatched braces) */
    if ( actual == NULL && expected == NULL ) {
        return result;
    }

    /*
     * otherwise we should have identical lists of null terminated strings,
     * with each list also ending in a pointer to null.
     */
    for ( a = actual, b = expected; *a != NULL && *b != NULL; a++, b++ ) {
        if ( strcmp(*a, *b) != 0 ) {
            result = 0;
            break;
        }

        free(*a);
        free(*b);
    }

    /* either string not being null means they didn't match */
    if ( *a != NULL || *b != NULL ) {
        result = 0;
    }

    free(actual);
    free(expected);

    return result;
}



/*
 * Test the test argument parsing.
 */
int main(void) {

    /* simple flags and arguments */
    assert(check_parse(""));
    assert(check_parse("one-word"));
    assert(check_parse("two words"));
    assert(check_parse("five words separated by whitespace"));
    assert(check_parse("-a"));
    assert(check_parse("-a with-argument"));
    assert(check_parse("-long-option"));
    assert(check_parse("-long-option with argument"));
    assert(check_parse("--long-argument"));
    assert(check_parse("--long-option with argument"));
    assert(check_parse("-a -b 123 -long1 --long2 --long3 args"));

    /* quoted arguments */
    assert(check_parse("''"));
    assert(check_parse("'one-word'"));
    assert(check_parse("'two words'"));
    assert(check_parse("'two words' with more after"));
    assert(check_parse("space separated words followed by 'two words'"));
    assert(check_parse("run-together'words with quotes'around-some"));
    assert(check_parse("-a 'multi word argument in single quotes'"));
    assert(check_parse("-a \"multi word argument in double quotes\""));

    /* escaped quotes */
    assert(check_parse("\'\'"));
    assert(check_parse("\"\""));
    assert(check_parse("\'escaped single quotes\'"));
    assert(check_parse("\"escaped double quotes\""));
    assert(check_parse("\\\'doubly escaped single quotes\\\'"));
    assert(check_parse("\\\"doubly escaped double quotes\\\""));
    assert(check_parse("'mix and match \"quote styles\"'"));
    assert(check_parse("embed more \"quotes \\\"within\\\" quotes\""));

    /* unbalanced quotes */
    assert(check_parse("unbalanced 'single quotes"));
    assert(check_parse("unbalanced 'single quotes"));
    assert(check_parse("unbalanced single quotes'"));
    assert(check_parse("'unbalanced single quotes"));
    assert(check_parse("unbalanced \"double quotes"));
    assert(check_parse("unbalanced double quotes\""));
    assert(check_parse("\"unbalanced double quotes"));

    return 0;
}
