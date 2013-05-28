testdir=$(prefix)/tests

bin_PROGRAMS=skeleton
skeleton_SOURCES=skeleton.c ../testmain.c
skeleton_LDADD=-L../../common/ -lamp

test_LTLIBRARIES=skeleton.la
skeleton_la_SOURCES=skeleton.c
skeleton_la_CFLAGS=-rdynamic
skeleton_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../common/
