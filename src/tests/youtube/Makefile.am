EXTRA_DIST=*.h youtube.proto yt.html
#SUBDIRS= . test
SUBDIRS= .
BUILT_SOURCES=youtube.pb-c.c
CLEANFILES=youtube.pb-c.c youtube.pb-c.h

if WANT_YOUTUBE_TEST
testdir=$(libdir)/$(PACKAGE)/tests
bin_PROGRAMS=amp-youtube
amp_youtube_SOURCES=../testmain.c
amp_youtube_LDADD=youtube.la -L../../common/ -lamp -lprotobuf-c -lunbound -lwebsockets -lcurl -ljansson

test_LTLIBRARIES=youtube.la
youtube_la_SOURCES=youtube.c
nodist_youtube_la_SOURCES=youtube.pb-c.c
youtube_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c -lwebsockets -ljansson -lcurl

install-exec-local:
	mkdir -p $(DESTDIR)/$(libdir)/$(PACKAGE)/extra
	cp yt.html $(DESTDIR)/$(libdir)/$(PACKAGE)/extra/
endif

youtube.pb-c.c: youtube.proto
	protoc-c --c_out=. youtube.proto
	protoc --python_out=../python/ampsave/tests/ youtube.proto
