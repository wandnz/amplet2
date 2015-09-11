EXTRA_DIST=*.h lexer.l http.proto
SUBDIRS= . test
BUILT_SOURCES=http.pb-c.c
CLEANFILES=http.pb-c.c http.pb-c.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-http
amp_http_SOURCES=../testmain.c
amp_http_LDADD=http.la -L../../common/ -lamp -lcurl -lprotobuf-c

test_LTLIBRARIES=http.la
http_la_SOURCES=http.c servers.c parsers.c output.c lexer.l
nodist_http_la_SOURCES=http.pb-c.c
http_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lcurl -lprotobuf-c

INCLUDES=-I../ -I../../common/

http.pb-c.c: Makefile
	protoc-c --c_out=. http.proto
	protoc --python_out=../python/ampsave.tests/ http.proto
