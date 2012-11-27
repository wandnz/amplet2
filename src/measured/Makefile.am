SUBDIRS= . tests

EXTRA_DIST=*.h

bin_PROGRAMS=measured
measured_SOURCES=measured.c schedule.c watchdog.c test.c nametable.c
measured_LDFLAGS=-lmeasured

libmeasureddir=$(libdir)
libmeasured_LTLIBRARIES=libmeasured.la
libmeasured_la_SOURCES=amp_exec.c debug.c
libmeasured_la_LDFLAGS=-module -avoid-version
