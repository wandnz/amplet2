SUBDIRS= .

if WANT_SKELETON_TEST
SUBDIRS+=skeleton
endif

if WANT_ICMP_TEST
SUBDIRS+=icmp
endif

if WANT_DNS_TEST
SUBDIRS+=dns
endif

if WANT_TRACEROUTE_TEST
SUBDIRS+=traceroute
endif

if WANT_HTTP_TEST
SUBDIRS+=http
endif

if WANT_THROUGHPUT_TEST
SUBDIRS+=throughput
endif

if WANT_TCPPING_TEST
SUBDIRS+=tcpping
endif

if WANT_REMOTESKELETON_TEST
SUBDIRS+=remoteskeleton
endif

if WANT_UDPSTREAM_TEST
SUBDIRS+=udpstream
endif

# Always include the currently disabled youtube test, so that the python
# scripts get built and included.
# TODO: what is the best way to always build the server-side python scripts
# while only building the rest of the test if it is enabled?
SUBDIRS+=youtube
SUBDIRS+=fastping

if WANT_PYTHON
SUBDIRS+=python
endif
