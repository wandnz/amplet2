EXTRA_DIST=*.h fastping.proto
SUBDIRS= . test
BUILT_SOURCES=fastping.pb-c.c
CLEANFILES=fastping.pb-c.c fastping.pb-c.h

if WANT_FASTPING_TEST

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-fastping
amp_fastping_SOURCES=../testmain.c
amp_fastping_LDADD=fastping.la -L../../common/ -lamp -lprotobuf-c -lunbound

test_LTLIBRARIES=fastping.la
fastping_la_SOURCES=fastping.c
nodist_fastping_la_SOURCES=fastping.pb-c.c
fastping_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c -lm -lpcap

install-exec-hook:
	setcap 'CAP_NET_RAW=ep' $(DESTDIR)/$(bindir)/amp-fastping || true

endif

fastping.pb-c.c: fastping.proto
	protoc-c --c_out=. fastping.proto
	protoc --python_out=../python/ampsave/tests/ fastping.proto
