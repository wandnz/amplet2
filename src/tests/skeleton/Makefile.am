EXTRA_DIST=skeleton.proto

BUILT_SOURCES=skeleton.pb-c.c
CLEANFILES=skeleton.pb-c.c skeleton.pb-c.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-skeleton
amp_skeleton_SOURCES=../testmain.c
amp_skeleton_LDADD=skeleton.la -L../../common/ -lamp -lprotobuf-c -lunbound

test_LTLIBRARIES=skeleton.la
skeleton_la_SOURCES=skeleton.c
nodist_skeleton_la_SOURCES=skeleton.pb-c.c
skeleton_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c

skeleton.pb-c.c: skeleton.proto
	protoc-c --c_out=. skeleton.proto
	protoc --python_out=../python/ampsave/tests/ skeleton.proto
