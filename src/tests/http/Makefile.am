EXTRA_DIST=*.h lexer.l

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-http
amp_http_SOURCES=http.c servers.c parsers.c output.c ../testmain.c lexer.l
amp_http_LDADD=-L../../common/ -lamp -lcurl

test_LTLIBRARIES=http.la
http_la_SOURCES=http.c servers.c parsers.c output.c lexer.l
http_la_CFLAGS=-rdynamic
http_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lcurl

INCLUDES=-I../ -I../../common/
