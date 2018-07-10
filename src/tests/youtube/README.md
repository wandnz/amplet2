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

Chromium tag 63.0.3239.150 was used to build the libraries that we link
against, plus the following patches to fix bugs and make it work with g++:
 - https://chromium.googlesource.com/chromium/src.git/+/7a9777223774930b2cb8158dc669051298ea277e%5E%21/
 - https://chromium.googlesource.com/chromium/src/+/5a9c3a34781b010bc2e4b29c3867159756339317%5E%21/
 - https://groups.google.com/a/chromium.org/d/msg/chromium-dev/OOTWBusBqGQ/2udlu6zhBwAJ
 - https://github.com/wanduow/amplet2/tree/develop/src/tests/youtube/extra/render_process_host_impl.patch

The official [Linux build instructions](https://chromium.googlesource.com/chromium/src/+/lkcr/docs/linux_build_instructions.md)
should cover everything required.

The args.gn file used to build the Chromium libraries for use with AMP was:

    import("//build/args/headless.gn")
    is_debug = false
    symbol_level = 0
    is_component_build = true
    remove_webcore_debug_symbols = true
    enable_nacl = false
    is_clang = false
    use_sysroot = false
    use_allocator = "none"
    treat_warnings_as_errors = false

You don't need to build the entirety of Chromium, just enough to get the
headless libraries and their dependencies built:

    $ ninja -C out/Default headless_shell

Once you have built the Chromium source you can then change to the directory
containing the amplet2-client source and build the YouTube test:

    $ ./configure --enable-youtube --with-chromium-build=/path/to/chromium/src/out/Default --with-chromium-includes=/path/to/chromium/src
    $ make


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
