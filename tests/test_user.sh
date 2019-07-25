#!/bin/bash

. tests/test_helper.sh

# check non-privileged amplet user exists
test_amplet_user() {
    assertTrue "getent passwd amplet > /dev/null"
}

. /usr/share/shunit2/shunit2
