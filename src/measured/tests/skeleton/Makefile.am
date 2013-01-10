testdir=$(prefix)/tests

bin_PROGRAMS=skeleton
skeleton_SOURCES=skeleton.c ../testmain.c
skeleton_LDFLAGS=-L../../.libs/ -lmeasured
skeleton_LDADD=-L../../.libs/ -lmeasured

test_LTLIBRARIES=skeleton.la
skeleton_la_SOURCES=skeleton.c
skeleton_la_CFLAGS=-rdynamic
skeleton_la_LDFLAGS=-module -avoid-version -L../../.libs/ -lmeasured

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../../
