EXTRA_DIST=*.h sip.proto extra/*
SUBDIRS=.
BUILT_SOURCES=sip.pb-c.c
CLEANFILES=sip.pb-c.c sip.pb-c.h

if WANT_SIP_TEST

SUBDIRS+=test
testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-sip
amp_sip_SOURCES=../testmain.c
amp_sip_LDADD=sip.la -L../../common/ -lamp -lprotobuf-c -lunbound

test_LTLIBRARIES=sip.la
sip_la_SOURCES=sip.c sip_common.c sip_server.c sip_client.c
nodist_sip_la_SOURCES=sip.pb-c.c
sip_la_CFLAGS=$(AM_CFLAGS) -DPJ_AUTOCONF=1
sip_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c -lpj -lpjsua -lpjsip -lpjmedia

install-exec-local:
	mkdir -p $(DESTDIR)/$(libdir)/$(PACKAGE)/extra
	cp extra/sip-test-8000.wav $(DESTDIR)/$(libdir)/$(PACKAGE)/extra
endif

sip.pb-c.c: sip.proto
	protoc-c --c_out=. sip.proto
	protoc --python_out=../python/ampsave/tests/ sip.proto
