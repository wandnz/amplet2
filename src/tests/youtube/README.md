# AMP YouTube Test

This test uses headless Chromium to fetch and play a video from YouTube.
Basing the test around a real web browser helps make it as accurate as
possible by using the same tools as users themselves. However it doesn't
need a user to click any links, nor does it need any sort of graphical
output to display the video.


## Timing Web Page

YouTube has a [JavaScript API](https://developers.google.com/youtube/iframe_api_reference)
that allows controlling a video player embedded
in an IFrame. This API also notifies when certain events occur, such as video
playback beginning, buffering, or video quality changes. Using this we can
create a web page that will download a given video and report on many aspects
of the process.

The test currently ships with a copy of this [web page](https://github.com/wanduow/amplet2/tree/develop/src/tests/youtube/extra/yt.html) that it loads from disk.


## Headless Chromium

Chrome added headless operation in version 59.

### Building Libraries

Chromium 71.0.3578.98 was used to build the Ubuntu libraries that we link
against, specifically because it is the current version available in Ubuntu
Xenial and Bionic. The same patches to the source used by the Ubuntu packages
were also applied. Brief build instructions follow, based on the package build.

Install build dependencies:

    apt-get install debhelper dh-buildinfo ninja-build pkg-config lsb-release quilt python bison clang-6.0 llvm-6.0 gperf libpulse-dev libnss3-dev mesa-common-dev libpci-dev libxtst-dev libxss-dev libgtk-3-dev libglib2.0-dev libgnome-keyring-dev libudev-dev libdrm-dev libcap-dev libgcrypt-dev libkrb5-dev libxkbcommon-dev libpam0g-dev libffi-dev uuid-dev chrpath yasm

Download source:

    wget http://archive.ubuntu.com/ubuntu/pool/universe/c/chromium-browser/chromium-browser_71.0.3578.98.orig.tar.xz
    tar xJvf chromium-browser_71.0.3578.98.orig.tar.xz
    cd chromium-71.0.3578.98/
    wget http://archive.ubuntu.com/ubuntu/pool/universe/c/chromium-browser/chromium-browser_71.0.3578.98-0ubuntu0.16.04.1.debian.tar.xz
    tar xJvf chromium-browser_71.0.3578.98-0ubuntu0.16.04.1.debian.tar.xz

Apply patches:

    for i in `cat debian/patches/series`; do patch -p1 <debian/patches/$i; done

Build headless libraries (with the option to use a full featured libffmpeg.so):

    mkdir -p out/Release
    CC=clang-6.0 CXX=clang++-6.0 AR=llvm-ar-6.0 tools/gn/bootstrap/bootstrap.py --verbose --no-rebuild --build-path=out/Release --gn-gen-args 'import("//build/args/headless.gn") enable_hangout_services_extension=true enable_mdns=true enable_nacl=false enable_wayland_server=false enable_widevine=true fieldtrial_testing_like_official_build=true is_component_build=true is_component_ffmpeg=true is_debug=false is_desktop_linux=true is_official_build=false remove_webcore_debug_symbols=true symbol_level=0 treat_warnings_as_errors=false use_allocator="none" use_aura=true use_gio=true use_glib=true use_gold=false use_libpci=true use_pulseaudio=false use_sysroot=false use_system_harfbuzz=false use_system_libjpeg=false rtc_enable_protobuf=false rtc_use_h264=true is_clang=true clang_base_path="/usr" clang_use_chrome_plugins=false use_lld=false is_cfi=false use_thin_lto=false fatal_linker_warnings=false target_os="linux" current_os="linux" optimize_webui=false proprietary_codecs=true ffmpeg_branding="Chrome" target_cpu="x64"'
    ninja -j 2 -C out/Release headless_shell

Build libffmpeg.so (without h264, so we can distribute it):

    mkdir -p out/ffmpeg-std
    out/Release/gn gen out/ffmpeg-std/ --args='import("//build/args/headless.gn") enable_hangout_services_extension=true enable_mdns=true enable_nacl=false enable_wayland_server=false enable_widevine=true fieldtrial_testing_like_official_build=true is_component_build=true is_component_ffmpeg=true is_debug=false is_desktop_linux=true is_official_build=false remove_webcore_debug_symbols=true symbol_level=0 treat_warnings_as_errors=false use_allocator="none" use_aura=true use_gio=true use_glib=true use_gold=false use_libpci=true use_pulseaudio=false use_sysroot=false use_system_harfbuzz=false use_system_libjpeg=false rtc_enable_protobuf=false rtc_use_h264=true is_clang=true clang_base_path="/usr" clang_use_chrome_plugins=false use_lld=false is_cfi=false use_thin_lto=false fatal_linker_warnings=false target_os="linux" current_os="linux" optimize_webui=false target_cpu="x64"'
    ninja -j 2 -C out/ffmpeg-std libffmpeg.so

Once you have built the Chromium source you can then change to the directory
containing the amplet2-client source and build the YouTube test:

    echo "deb http://amp.wand.net.nz/debian/ `lsb_release -c -s` main" |
            sudo tee /etc/apt/sources.list.d/amplet2.list
    wget -O- http://amp.wand.net.nz/debian/pubkey.gpg | sudo apt-key add -
    apt-get update
    apt-get install autotools-dev python libunbound-dev libssl-dev libpcap-dev libyaml-dev libprotobuf-c-dev protobuf-c-compiler protobuf-compiler dh-systemd libconfuse-dev libcurl4-openssl-dev librabbitmq-dev python-setuptools flex automake libtool libwandevent-dev clang-6.0 libexpat1-dev zlib1g-dev pkg-config libnss3-dev python lsb-release libnspr4-dev lld-6.0 libglib2.0-dev
    ln -s /usr/bin/clang-6.0 /usr/bin/clang # TODO fix clang location
    ln -s /usr/bin/clang++-6.0 /usr/bin/clang++ # TODO fix clang location
    tar xzvf amplet2-X.Y.Z
    cd amplet2-X.Y.Z
    ./configure --enable-youtube --with-chromium-build=/path/to/chromium/src/out/Default --with-chromium-includes=/path/to/chromium/src
    make


### Chromium Zygote Processes

The initial Chromium process is [forked repeatedly](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/linux_zygote.md) to create new renderers etc
as the browser is used. This helps the new processes start faster (as much of
the initialisation has already been performed) and provides a stable reference
to the binary and shared libraries that won't be changed from underneath the
running process.

Unfortunately this doesn't work well when run from the amplet2
scheduler as it forks `/proc/self/exe` expecting to find a Chromium process but
instead finds amplet2. Using `prctl()` to replace `/proc/self/exe` looked
promising but would only succeed within a docker environment. Setting
`--no-zygote` and `--single-process` worked until updates to Chromium appear
to have made it impossible to prevent at least an initial fork. The test now
forks and execs to a small wrapper program that runs the browser (and
behaves sensibly when re-forked for zygotes, renderers etc)


### Accessing JavaScript Results

The JavaScript results made available by the web page can be fetched by the
test using the [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/),
within the headless browser. These are processed and written to shared memory
for the parent process to extract, annotate and report to the collector.


## README TODO
- discuss symbol conflicts (libssl vs libboringssl) and workarounds (dlmopen,
linking order, fork+exec)
- discuss linker issues - ld vs gold
- discuss compiler issues - clang vs gcc/g++
- expand information around the timing web page
- expand information around devtools, fetching results within the browser
