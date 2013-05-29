EXTRA_DIST=*.h

# TODO: There is probably a better way to do this so we can override them
# individually on the command line without having to override them all.
# This works for now to make sure that files can always be found if prefix
# is changed, but will need to be fixed in the near future.
#AM_CFLAGS=-DAMP_CONFIG_DIR=\"$(prefix)/etc\"
#AM_CFLAGS+=-DAMP_TEST_DIRECTORY=\"$(prefix)/tests\"

bin_PROGRAMS=measured
measured_SOURCES=measured.c schedule.c watchdog.c test.c nametable.c refresh.c
measured_CFLAGS=-I../tests/ -I../common/ -DAMP_CONFIG_DIR=\"$(sysconfdir)/$(PACKAGE)\" -DAMP_TEST_DIRECTORY=\"$(libdir)/$(PACKAGE)/tests\" -rdynamic
measured_LDFLAGS=-L../tests/ -L../common/ -lamp

etcdir=$(sysconfdir)/$(PACKAGE)
dist_etc_DATA=etc/*
sharedir=$(pkgdatadir)/rsyslog
dist_share_DATA=rsyslog/*

