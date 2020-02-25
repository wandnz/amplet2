EXTRA_DIST=*.h controlmsg.proto measured.proto
SUBDIRS= . test
BUILT_SOURCES=controlmsg.pb-c.c measured.pb-c.c
CLEANFILES=controlmsg.pb-c.c controlmsg.pb-c.h measured.pb-c.c measured.pb-c.h

# XXX should this be just a static library? doesn't really need to be a shared
# object that gets installed into the system...
libampdir=$(libdir)
libamp_LTLIBRARIES=libamp.la
libamp_la_SOURCES=debug.c modules.c testlib.c ssl.c ssl_common_name.c ampresolv.c asn.c iptrie.c serverlib.c controlmsg.c icmpcode.c dscp.c usage.c checksum.c
nodist_libamp_la_SOURCES=controlmsg.pb-c.c measured.pb-c.c
libamp_la_LDFLAGS=-version-info @LIBAMP_LIBTOOL_VERSION@ -lunbound -lpthread -lssl -lcrypto -lprotobuf-c

controlmsg.pb-c.c: controlmsg.proto
	protoc-c --c_out=. controlmsg.proto

measured.pb-c.c: measured.proto
	protoc-c --c_out=. measured.proto
