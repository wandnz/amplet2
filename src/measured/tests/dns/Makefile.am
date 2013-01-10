testdir=$(prefix)/tests

bin_PROGRAMS=dns
dns_SOURCES=dns.c ../testmain.c
dns_LDFLAGS=-L../../.libs/ -lmeasured
dns_LDADD=-L../../.libs/ -lmeasured

test_LTLIBRARIES=dns.la
dns_la_SOURCES=dns.c
dns_la_CFLAGS=-rdynamic
dns_la_LDFLAGS=-module -avoid-version -L../../.libs/ -lmeasured

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../../ -I../
