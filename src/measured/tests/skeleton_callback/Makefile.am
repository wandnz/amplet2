EXTRA_DIST=*.h

testdir=$(prefix)/tests/

bin_PROGRAMS=skeleton_callback
skeleton_callback_SOURCES=skeleton_callback.c

test_LTLIBRARIES=skeleton_callback.la
skeleton_callback_la_SOURCES=register_skeleton_callback.c
skeleton_callback_la_LDFLAGS=-module -avoid-version

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../../
