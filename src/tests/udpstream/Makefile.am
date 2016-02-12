EXTRA_DIST=*.h udpstream.proto
#SUBDIRS= . test
BUILT_SOURCES=udpstream.pb-c.c
CLEANFILES=udpstream.pb-c.c udpstream.pb-c.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-udpstream
amp_udpstream_SOURCES=../testmain.c
amp_udpstream_LDADD=udpstream.la -L../../common/ -lamp -lprotobuf-c -lunbound

test_LTLIBRARIES=udpstream.la
udpstream_la_SOURCES=udpstream.c udpstream_server.c udpstream_client.c udpstream_common.c
nodist_udpstream_la_SOURCES=udpstream.pb-c.c
udpstream_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c

INCLUDES=-I../ -I../../common/

udpstream.pb-c.c: Makefile
	protoc-c --proto_path=../../ --proto_path=. --c_out=. udpstream.proto
	protoc --proto_path=../../ --proto_path=. --python_out=../python/ampsave/tests/ udpstream.proto
