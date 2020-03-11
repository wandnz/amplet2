EXTRA_DIST=*.h udpstream.proto
SUBDIRS= . test
BUILT_SOURCES=udpstream.pb-c.c
CLEANFILES=udpstream.pb-c.c udpstream.pb-c.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-udpstream
amp_udpstream_SOURCES=../testmain.c
amp_udpstream_LDADD=udpstream.la -L../../common/ -lamp -lprotobuf-c -lunbound
amp_udpstream_LDFLAGS=-Wl,--no-as-needed

test_LTLIBRARIES=udpstream.la
udpstream_la_SOURCES=udpstream.c udpstream_server.c udpstream_client.c udpstream_common.c
nodist_udpstream_la_SOURCES=udpstream.pb-c.c
udpstream_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c -lm

INCLUDES=-I../ -I../../common/

install-exec-hook:
	setcap 'CAP_NET_BIND_SERVICE=ep' $(DESTDIR)/$(bindir)/amp-udpstream

udpstream.pb-c.c: udpstream.proto
	protoc-c --c_out=. udpstream.proto
	protoc --python_out=../python/ampsave/tests/ udpstream.proto
