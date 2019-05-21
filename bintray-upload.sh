#!/bin/bash

set -e -o pipefail

BINTRAY_DEB_REPO="wand/amp"
BINTRAY_RPM_REPO="wand/amp-rpm"
BINTRAY_LICENSE="GPL-2.0"

apt-get update && apt-get install -y curl rpm

curl --silent -fL -XGET \
    "https://api.bintray.com/content/jfrog/jfrog-cli-go/\$latest/jfrog-cli-linux-amd64/jfrog?bt_package=jfrog-cli-linux-amd64" \
    > /usr/local/bin/jfrog
chmod +x /usr/local/bin/jfrog
mkdir ~/.jfrog/
cat << EOF > ~/.jfrog/jfrog-cli.conf
{
  "artifactory": null,
  "bintray": {
    "user": "${BINTRAY_USERNAME}",
    "key": "${BINTRAY_API_KEY}"
  },
  "Version": "1"
}
EOF

for path in `find built-packages/ -maxdepth 1 -type d`; do
    IFS=_ read linux_version <<< $(basename "${path}")
    for pkg in `find "${path}" -maxdepth 1 -type f`; do
        pkg_extension=${pkg##*.}
        pkg_filename=$(basename "${pkg}")

        if [ "$pkg_extension" = "deb" ]; then
            IFS=_ read pkg_name pkg_version pkg_arch <<< $(basename -s ".deb" "${pkg_filename}")
            jfrog bt package-create --licenses "${BINTRAY_LICENSE}" --vcs-url "${CI_PROJECT_URL}" "${BINTRAY_DEB_REPO}/${pkg_name}" || true
            jfrog bt upload --publish --deb "${linux_version}/main/${pkg_arch}" "${pkg}" "${BINTRAY_DEB_REPO}/${pkg_name}/${pkg_version}" "pool/${linux_version}/main/${pkg_name}/"
        fi

        if [ "$pkg_extension" = "rpm" ]; then
            IFS=_ read rpm_distribution rpm_releasever <<< $linux_version
            read pkg_name pkg_version pkg_arch <<< $(rpm -pq ${pkg} --queryformat "%{NAME} %{VERSION}-%{RELEASE} %{ARCH}")
            pkg_version=${pkg_version%.*}

            jfrog bt package-create --licenses "${BINTRAY_LICENSE}" --vcs-url "${CI_PROJECT_URL}" "${BINTRAY_RPM_REPO}/${pkg_name}" || true
            jfrog bt upload --publish "${pkg}" "${BINTRAY_RPM_REPO}/${pkg_name}/${pkg_version}" "${rpm_distribution}/${rpm_releasever}/${pkg_arch}/Packages/${pkg_name}/"
        fi
    done
done
