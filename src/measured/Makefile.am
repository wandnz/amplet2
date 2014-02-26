EXTRA_DIST=*.h
SUBDIRS=. etc test

# TODO: There is probably a better way to do this so we can override them
# individually on the command line without having to override them all.
# This works for now to make sure that files can always be found if prefix
# is changed, but will need to be fixed in the near future.
#AM_CFLAGS=-DAMP_CONFIG_DIR=\"$(prefix)/etc\"
#AM_CFLAGS+=-DAMP_TEST_DIRECTORY=\"$(prefix)/tests\"

bin_PROGRAMS=amplet2
amplet2_SOURCES=measured.c schedule.c watchdog.c test.c nametable.c control.c
amplet2_CFLAGS=-I../tests/ -I../common/ -DAMP_CONFIG_DIR=\"$(sysconfdir)/$(PACKAGE)\" -DAMP_TEST_DIRECTORY=\"$(libdir)/$(PACKAGE)/tests\" -rdynamic
amplet2_LDFLAGS=-L../tests/ -L../common/ -lamp -lcurl

sharedir=$(pkgdatadir)/rsyslog
dist_share_DATA=rsyslog/*

