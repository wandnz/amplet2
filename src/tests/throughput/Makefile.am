EXTRA_DIST=*.h

testdir=$(libdir)/$(PACKAGE)/tests

#bin_PROGRAMS=throughput_client throughput_server throughput
#throughput_client_SOURCES=throughput_common.c web10g.c ../testmain.c
#throughput_client_LDADD=-L../../common/ -lamp

#throughput_server_SOURCES=throughput_server.c throughput_common.c web10g.c
#throughput_server_LDADD=-L../../common/ -lamp

bin_PROGRAMS=throughput
throughput_SOURCES=throughput_server.c throughput_common.c throughput_client.c web10g.c ../testmain.c
throughput_LDADD=-L../../common/ -lamp

test_LTLIBRARIES=throughput.la
throughput_la_SOURCES=throughput_server.c throughput_common.c throughput_client.c web10g.c
throughput_la_CFLAGS=-rdynamic
throughput_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp



INCLUDES=-I../ -I../../common/

if HAVE_ESTATS
#throughput_client_LDADD += -lestats
#throughput_server_LDADD += -lestats
throughput_LDADD += -lestats
throughput_la_LDFLAGS += -lestats
AM_CPPFLAGS = -DHAVE_ESTATS
endif
