EXTRA_DIST=*.h
SUBDIRS= .

libmeasureddir=$(libdir)
libmeasured_LTLIBRARIES=libmeasured.la
libmeasured_la_SOURCES=testlib.c
libmeasured_la_CFLAGS=-I../common/
libmeasured_la_LDFLAGS=-module -avoid-version -lrabbitmq -L../common/ -lamp

if WANT_SKELETON_TEST
SUBDIRS+=skeleton
endif

if WANT_SKELETON_CALLBACK_TEST
SUBDIRS+=skeleton_callback
endif

if WANT_ICMP_TEST
SUBDIRS+=icmp
endif

if WANT_DNS_TEST
SUBDIRS+=dns
endif
