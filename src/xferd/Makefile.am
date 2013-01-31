EXTRA_DIST=*.h

# TODO: There is probably a better way to do this so we can override them
# individually on the command line without having to override them all.
# This works for now to make sure that files can always be found if prefix
# is changed, but will need to be fixed in the near future.
#AM_CFLAGS=-DAMP_CONFIG_DIR=\"$(prefix)/etc\"
#AM_CFLAGS+=-DAMP_TEST_DIRECTORY=\"$(prefix)/tests\"

# TODO move messaging files somewhere sensible
bin_PROGRAMS=xferd
xferd_SOURCES=xferd.c consumer.c
xferd_CFLAGS=-I../common/
xferd_CFLAGS+=-DAMP_CONFIG_DIR=\"$(prefix)/etc\"
xferd_CFLAGS+=-DAMP_TEST_DIRECTORY=\"$(prefix)/tests\"
xferd_LDFLAGS=-L../common/ -lrabbitmq -lamp
