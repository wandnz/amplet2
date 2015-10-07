testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-skeleton
amp_skeleton_SOURCES=skeleton.c ../testmain.c
amp_skeleton_LDADD=-L../../common/ -lamp -lunbound

test_LTLIBRARIES=skeleton.la
skeleton_la_SOURCES=skeleton.c
skeleton_la_CFLAGS=-rdynamic
skeleton_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp

INCLUDES=-I../ -I../../common/
