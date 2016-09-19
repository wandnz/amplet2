EXTRA_DIST=*.h
SUBDIRS=. etc test

bin_PROGRAMS=amplet2 amplet2-remote

amplet2_SOURCES=measured.c schedule.c watchdog.c run.c nametable.c control.c rabbitcfg.c nssock.c asnsock.c localsock.c certs.c parseconfig.c acl.c messaging.c
amplet2_CFLAGS=-I../tests/ -I../common/ -D_GNU_SOURCE -DAMP_CONFIG_DIR=\"$(sysconfdir)/$(PACKAGE)\" -DAMP_TEST_DIRECTORY=\"$(libdir)/$(PACKAGE)/tests\" -DAMP_RUN_DIR=\"$(localstatedir)/run/$(PACKAGE)\" -rdynamic
amplet2_LDFLAGS=-L../tests/ -L../common/ -lamp -lcurl -lwandevent -lconfuse -lpthread -lunbound -lyaml -lssl -lcrypto -lrt -lrabbitmq

amplet2_remote_SOURCES=remote-client.c
amplet2_remote_CFLAGS=-I../common/ -D_GNU_SOURCE -DAMP_TEST_DIRECTORY=\"$(libdir)/$(PACKAGE)/tests\" -rdynamic
amplet2_remote_LDFLAGS=-L../common/ -lamp -lssl -lcrypto -lprotobuf-c

sharedir=$(pkgdatadir)/rsyslog
dist_share_DATA=rsyslog/*

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/run/$(PACKAGE)
