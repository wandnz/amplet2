EXTRA_DIST=*.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-tcpping
amp_tcpping_SOURCES=pcapcapture.c tcpping.c ../testmain.c
amp_tcpping_LDADD=-L../../common/ -lamp -lwandevent -lpcap

test_LTLIBRARIES=tcpping.la
tcpping_la_SOURCES=pcapcapture.c tcpping.c
tcpping_la_CFLAGS=-rdynamic
tcpping_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lwandevent \
                -lpcap

INCLUDES=-I../ -I../../common/

