EXTRA_DIST=*.h
SUBDIRS=. etc test

bin_PROGRAMS=amplet2 amplet2-remote

amplet2_SOURCES=measured.c schedule.c watchdog.c run.c nametable.c control.c rabbitcfg.c nssock.c asnsock.c localsock.c certs.c parseconfig.c acl.c messaging.c users.c
amplet2_CFLAGS=-I../tests/ -I../common/ -D_GNU_SOURCE -DAMP_CONFIG_DIR=\"$(sysconfdir)/$(PACKAGE)\" -DAMP_TEST_DIRECTORY=\"$(libdir)/$(PACKAGE)/tests\" -DAMP_RUN_DIR=\"$(localstatedir)/run/$(PACKAGE)\" -rdynamic
amplet2_LDFLAGS=-L../tests/ -L../common/ -lamp -lcurl -lwandevent -lconfuse -lpthread -lunbound -lyaml -lssl -lcrypto -lrt -lrabbitmq -lcap

amplet2_remote_SOURCES=remote-client.c
amplet2_remote_CFLAGS=-I../common/ -D_GNU_SOURCE -DAMP_TEST_DIRECTORY=\"$(libdir)/$(PACKAGE)/tests\" -rdynamic
amplet2_remote_LDFLAGS=-L../common/ -lamp -lssl -lcrypto -lprotobuf-c

syslogdir=$(pkgdatadir)/rsyslog
dist_syslog_DATA=rsyslog/*

rabbitdir=$(pkgdatadir)/rabbitmq
dist_rabbit_DATA=rabbitmq/*

install-exec-local:
	setcap 'CAP_NET_ADMIN=ep CAP_NET_BIND_SERVICE=ep CAP_NET_RAW=ep' $(DESTDIR)/$(bindir)/amplet2

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/run/$(PACKAGE)
