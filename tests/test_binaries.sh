#!/bin/bash

. tests/test_helper.sh

operator="+"
allcaps=" = "

# getcap output changed in v2.41, which is currently only used by bullseye
if [ "$CODENAME" = "bullseye" ]; then
    operator="="
    allcaps=" "
fi

# check capabilities of installed binaries are correct
test_capabilities() {
    declare -A capabilities=(
        ["/usr/sbin/amplet2"]="cap_net_bind_service,cap_net_admin,cap_net_raw${operator}ep"
        ["/usr/bin/amp-dns"]=""
        ["/usr/bin/amp-external"]=""
        ["/usr/bin/amp-fastping"]="cap_net_raw${operator}ep"
        ["/usr/bin/amp-http"]=""
        ["/usr/bin/amp-icmp"]="cap_net_raw${operator}ep"
        ["/usr/bin/amp-tcpping"]="cap_net_admin,cap_net_raw${operator}ep"
        ["/usr/bin/amp-throughput"]="cap_net_bind_service${operator}ep"
        ["/usr/bin/amp-trace"]="cap_net_raw${operator}ep"
        ["/usr/bin/amp-udpstream"]="cap_net_bind_service${operator}ep"
        ["/usr/bin/amplet2-remote"]=""
        )

    for bin in "${!capabilities[@]}"; do
        assertFileExists $bin

        cap=${capabilities[$bin]}
        out=`getcap ${bin}`
        if [ -z "$cap" ]; then
            assertEquals "" "$out"
        else
            assertEquals "${bin}${allcaps}${cap}" "$out"
        fi
    done
}

. /usr/share/shunit2/shunit2
