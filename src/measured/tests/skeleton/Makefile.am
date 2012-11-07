EXTRA_DIST=*.h

testdir=$(prefix)/tests/

bin_PROGRAMS=skeleton
skeleton_SOURCES=skeleton.c

test_LTLIBRARIES=skeleton.la
skeleton_la_SOURCES=register_skeleton.c
skeleton_la_LDFLAGS=-module -avoid-version

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../../
