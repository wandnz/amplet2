EXTRA_DIST=*.h lexer.l

testdir=$(prefix)/tests

bin_PROGRAMS=http
http_SOURCES=http.c servers.c parsers.c output.c ../testmain.c lexer.l
http_LDADD=-L../../common/ -lamp -lcurl

test_LTLIBRARIES=http.la
http_la_SOURCES=http.c servers.c parsers.c output.c lexer.l
http_la_CFLAGS=-rdynamic
http_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lcurl

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../common/
