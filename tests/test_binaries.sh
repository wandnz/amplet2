#!/bin/bash

. tests/test_helper.sh

# check capabilities of installed binaries are correct
test_capabilities() {
    declare -A capabilities=(
        ["/usr/sbin/amplet2"]="cap_net_bind_service,cap_net_admin,cap_net_raw+ep"
        ["/usr/sbin/amp-dns"]=""
        ["/usr/sbin/amp-external"]=""
        ["/usr/sbin/amp-fastping"]="cap_net_raw+ep"
        ["/usr/sbin/amp-http"]=""
        ["/usr/sbin/amp-icmp"]="cap_net_raw+ep"
        ["/usr/sbin/amp-tcpping"]="cap_net_admin,cap_net_raw+ep"
        ["/usr/sbin/amp-throughput"]="cap_net_bind_service+ep"
        ["/usr/sbin/amp-trace"]="cap_net_raw+ep"
        ["/usr/sbin/amp-udpstream"]="cap_net_bind_service+ep"
        ["/usr/sbin/amplet2-remote"]=""
        )

    for bin in "${!capabilities[@]}"; do
        assertFileExists $bin

        cap=${capabilities[$bin]}
        out=`getcap ${bin}`
        if [ -z "$cap" ]; then
            assertEquals "" "$out"
        else
            assertEquals "${bin} = ${cap}" "$out"
        fi
    done
}

. /usr/share/shunit2/shunit2
