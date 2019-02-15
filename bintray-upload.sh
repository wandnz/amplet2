#!/bin/bash

set -x -e -o pipefail

apt-get update && apt-get install -y curl

for path in `find built-packages/ -maxdepth 1 -type d`; do
    read dist_codename <<< $(basename "${path}")
    for deb in `find "${path}" -maxdepth 1 -type f`; do
        pkg_filename=$(basename "${deb}")
        IFS=_ read pkg_name pkg_version pkg_arch <<< $(basename -s ".deb" "${pkg_filename}")
        curl -T "${deb}" -u${BINTRAY_USERNAME}:${BINTRAY_API_KEY} \
        "https://api.bintray.com/content/wand/amp/${pkg_name}/${pkg_version}/pool/${dist_codename}/main/${pkg_name}/${pkg_filename};deb_distribution=${dist_codename};deb_component=main;deb_architecture=${pkg_arch};publish=1"
    done
done

