#!/bin/bash

. tests/test_helper.sh

# check directories exist and have correct permissions
test_config_dir() {
    declare -A directories=(
        ["/etc/amplet2"]="755"
        ["/etc/amplet2/clients"]="755"
        ["/etc/amplet2/keys"]="2750"
        ["/etc/amplet2/nametables"]="755"
        ["/etc/amplet2/schedules"]="755"
        )

    for dir in "${!directories[@]}"; do
        assertDirectoryExists $dir
        assertFileOwner "amplet" "$dir"
        assertFileGroup "amplet" "$dir"
        assertFilePermissions "${directories[$dir]}" "$dir"
    done
}

#test_client_config() {
#    assertFileExists "/etc/amplet2/clients/default.conf"
#}

. /usr/share/shunit2/shunit2
