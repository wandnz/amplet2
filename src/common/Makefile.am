EXTRA_DIST=*.h
SUBDIRS= . test

# XXX should this be just a static library? doesn't really need to be a shared
# object that gets installed into the system...
libampdir=$(libdir)
libamp_LTLIBRARIES=libamp.la
libamp_la_SOURCES=debug.c messaging.c modules.c testlib.c ssl.c ampresolv.c asn.c
libamp_la_LDFLAGS=-module -avoid-version -lrabbitmq -lunbound -lpthread
