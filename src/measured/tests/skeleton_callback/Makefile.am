testdir=$(prefix)/tests

bin_PROGRAMS=skeleton_callback
skeleton_callback_SOURCES=skeleton_callback.c ../testmain.c
skeleton_callback_LDFLAGS=-L../../.libs/ -lmeasured
skeleton_callback_LDADD=-L../../.libs/ -lmeasured

test_LTLIBRARIES=skeleton_callback.la
skeleton_callback_la_SOURCES=skeleton_callback.c
skeleton_callback_la_CFLAGS=-rdynamic
skeleton_callback_la_LDFLAGS=-module -avoid-version -L../../.libs/ -lmeasured

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../../
