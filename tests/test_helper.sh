#!/bin/bash

# TODO check number of args etc?
assertFileExists() {
    assertTrue "file $1 missing" "[ -f '$1' ]"
}

assertDirectoryExists() {
    assertTrue "directory $1 missing" "[ -d '$1' ]"
}

assertFileOwner() {
    assertEquals "wrong owner for $2," "$1" "`stat -c %U $2`"
}

assertFileGroup() {
    assertEquals "wrong group for $2," "$1" "`stat -c %G $2`"
}

assertFilePermissions() {
    assertEquals "wrong permissions for $2," "$1" "`stat -c %a $2`"
}
