EXTRA_DIST=*.h
SUBDIRS= . test
BUILT_SOURCES=servers.pb-c.c
CLEANFILES=servers.pb-c.c servers.pb-c.h

# XXX should this be just a static library? doesn't really need to be a shared
# object that gets installed into the system...
libampdir=$(libdir)
libamp_LTLIBRARIES=libamp.la
libamp_la_SOURCES=debug.c messaging.c modules.c testlib.c ssl.c ampresolv.c asn.c iptrie.c serverlib.c
nodist_libamp_la_SOURCES=servers.pb-c.c
libamp_la_LDFLAGS=-avoid-version -lrabbitmq -lunbound -lpthread -lssl -lcrypto -lprotobuf-c

servers.pb-c.c: Makefile
	protoc-c --c_out=. servers.proto
