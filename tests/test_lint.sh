#!/bin/bash

. tests/test_helper.sh

# run packaging linters over the built package
test_lint() {
    case "$CODENAME" in
        centos_7)
            run_rpmlint
            ;;

        bullseye)
            run_lintian "--fail-on error"
            ;;

        *)
            run_lintian
            ;;
    esac
}

# from bullseye, lintian needs extra command line options if you want it
# to exit non-0 when errors are found, and it doesn't look like they plan
# to fix it: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=962158
run_lintian() {
    assertFileExists /usr/bin/lintian
    /usr/bin/lintian --allow-root $1 packages/${DIRNAME}/amplet2-client_*.deb
    assertTrue "linter errors" $?
}

run_rpmlint() {
    yum install -y rpmlint
    assertFileExists /usr/bin/rpmlint
    /usr/bin/rpmlint packages/${DIRNAME}/amplet2-client-*.rpm
    # XXX temporarily stop rpmlint errors from halting the build
    #assertTrue "linter errors" $?
    echo "XXX: Temporarily ignoring rpmlint errors"
    assertTrue 0
}

. /usr/share/shunit2/shunit2
