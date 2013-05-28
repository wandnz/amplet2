EXTRA_DIST=*.h

testdir=$(prefix)/tests

bin_PROGRAMS=dns
dns_SOURCES=dns.c ../testmain.c
dns_LDADD=-L../../common/ -lamp

test_LTLIBRARIES=dns.la
dns_la_SOURCES=dns.c
dns_la_CFLAGS=-rdynamic
dns_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../common/
