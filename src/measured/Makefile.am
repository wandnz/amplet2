EXTRA_DIST=*.h
SUBDIRS=. etc test

sbin_PROGRAMS=amplet2
bin_PROGRAMS=amplet2-remote

amplet2_SOURCES=measured.c schedule.c watchdog.c run.c nametable.c control.c nssock.c asnsock.c localsock.c certs.c parseconfig.c acl.c messaging.c libevent_foreach.c
amplet2_LDFLAGS=-L../tests/ -L../common/ -lamp -lcurl -levent -lconfuse -lpthread -lunbound -lyaml -lssl -lcrypto -lrabbitmq $(AM_LDFLAGS)

amplet2_remote_SOURCES=remote-client.c
amplet2_remote_LDFLAGS=-L../common/ -lamp -lssl -lcrypto -lprotobuf-c $(AM_LDFLAGS)

if MINGW
amplet2_SOURCES+=w32-service.c
amplet2_LDFLAGS+=-liphlpapi
else
amplet2_SOURCES+=users.c rabbitcfg.c
amplet2_LDFLAGS+=-lrt -lcap
endif

INCLUDES=-I../tests/ -I../common/

syslogdir=$(pkgdatadir)/rsyslog
dist_syslog_DATA=rsyslog/*

rabbitdir=$(pkgdatadir)/rabbitmq
dist_rabbit_DATA=rabbitmq/*

if !MINGW
install-exec-hook:
	setcap 'CAP_NET_ADMIN=ep CAP_NET_BIND_SERVICE=ep CAP_NET_RAW=ep' $(DESTDIR)/$(sbindir)/amplet2
endif

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/run/$(PACKAGE)
