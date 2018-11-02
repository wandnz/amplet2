EXTRA_DIST=*.h youtube.proto extra/* README.md
#SUBDIRS= . test
SUBDIRS= .
BUILT_SOURCES=youtube.pb-c.c
CLEANFILES=youtube.pb-c.c youtube.pb-c.h

if WANT_YOUTUBE_TEST
CHROMIUM_LIBS=-lbase,-lipc,-lbindings,-lmojo_public_system_cpp,-lmojo_public_system,-lcontent,-lgpu,-lgles2_utils,-lgfx,-lskia,-lgeometry,-licui18n,-licuuc,-lrange,-lgl_wrapper,-lplatform,-lgl_init,-lui_base,-lui_data_pack,-levents_base,-lurl,-lbase_i18n,-lnet,-lprotobuf_lite,-lcrcrypto,-lboringssl,-lmedia,-lshared_memory_support,-lmojo_common_lib,-lgfx_ipc,-lgfx_ipc_geometry,-lgfx_ipc_skia,-lcapture_base,-lgfx_ipc_color,-lcc,-lui_base_ime,-ldisplay,-ldisplay_types,-lcapture_lib,-lcc_ipc,-laccessibility,-lsurface,-lurl_ipc,-lmojo_system_impl,-lstorage_common,-lstorage_browser,-lcompositor,-ldevices,-laura,-lozone,-lozone_base,-ldisplay_util,-levents,-lppapi_host,-lppapi_proxy,-lppapi_shared,-lblink_platform,-lblink_core,-lblink_modules,-lseccomp_bpf,-lsql,-lv8,-lv8_libbase,-lv8_libplatform,-lchromium_sqlite3,-lgesture_detection,-lwtf,-ltracing,-ldiscardable_memory_client,-lstartup_tracing,-lgles2_implementation,-lmedia_gpu,-lmidi,-lsandbox_services,-lsuid_sandbox_client,-lshell_dialogs,-lnative_theme,-lgin,-lcc_animation,-lcc_paint,-ldiscardable_memory_service,-lprefs,-ldevice_gamepad,-lgeolocation,-lsensors,-lsnapshot,-lui_touch_selection,-laura_extra,-lcc_blink,-ldevice_event_log,-lmedia_blink,-ljs,-lmojo_ime_lib,-lstub_window,-lffmpeg,-levents_ozone_layout,-lgl_in_process_context,-ldiscardable_memory_common,-lbluetooth,-lheadless,-lanimation,-lblink_common,-lcc_base,-lcc_debug,-lclient,-ldevice_base,-lembedder,-lhost,-lmanager,-lservice,-lblink_mojo_bindings_shared,-lblink_android_mojo_bindings_shared,-lcontent_public_common_mojo_bindings_shared,-linterfaces_shared,-lcontent_common_mojo_bindings_shared,-lviz_common,-lmedia_mojo_services,-lresource_coordinator_cpp,-lmessage_support,-lcolor_space,-lresource_coordinator_public_interfaces_internal_shared,-lembedder,-lservice_manager_cpp_types,-lservice_manager_mojom_blink,-lservice_manager_mojom_shared,-lservice_manager_mojom,-lviz_resource_format,-lcodec,-lmetrics_cpp,-lblink_offscreen_canvas_mojo_bindings_shared,-lgeometry_skia,-lservice_manager_cpp,-lfreetype_harfbuzz,-lprinting,-ldevice_vr_mojo_bindings_blink,-ldevice_vr_mojo_bindings,-ldevice_vr_mojo_bindings_shared,-lfingerprint,-lipc_mojom,-lipc_mojom_shared,-lsandbox,-lwm_public,-lcdm_manager,-lgfx_switches,-lembedder_switches,-lservice_manager_mojom_constants,-lwm,-lblink_controller,-lservice_manager_mojom_constants_shared

testdir=$(libdir)/$(PACKAGE)/tests
bin_PROGRAMS=amp-youtube amp-youtube-wrapper
amp_youtube_SOURCES=../testmain.c
amp_youtube_CFLAGS=-I../../common/
amp_youtube_LDADD=youtube.la
amp_youtube_LDFLAGS=-Wl,--disable-new-dtags -R $(libdir)/$(PACKAGE)/chromium -Wl,-fuse-ld=gold -L../../common/.libs/ -rdynamic -Wl,--start-group,${CHROMIUM_LIBS} -Wl,--end-group -Wl,--no-as-needed -L@CHROMIUM_BUILD_DIR@ -lrt -lnss3 -lnssutil3 -lsmime3 -lplds4 -lplc4 -lnspr4 -lstdc++ -ldl -lprotobuf-c -lboringssl -lssl -lamp -lunbound

amp_youtube_wrapper_SOURCES=wrapper.c
amp_youtube_wrapper_CFLAGS=-I../../common/ -D_GNU_SOURCE
amp_youtube_wrapper_LDADD=youtube.la
amp_youtube_wrapper_LDFLAGS=-Wl,--disable-new-dtags -R $(libdir)/$(PACKAGE)/chromium -Wl,-fuse-ld=gold -L../../common/.libs/ -rdynamic -Wl,--start-group,${CHROMIUM_LIBS} -Wl,--end-group -Wl,--no-as-needed -L@CHROMIUM_BUILD_DIR@ -lrt -lnss3 -lnssutil3 -lsmime3 -lplds4 -lplc4 -lnspr4 -lstdc++ -ldl -lprotobuf-c -lboringssl -lssl -lamp -lunbound

test_LTLIBRARIES=youtube.la
youtube_la_SOURCES=youtube.c chromium.cc
nodist_youtube_la_SOURCES=youtube.pb-c.c
youtube_la_CPPFLAGS=@CHROMIUM_INCLUDE_DIR@ -I../ -I../../common/  -fvisibility=hidden -fno-rtti -std=c++14 -fPIC -DUSE_SYMBOLIZE -DV8_DEPRECATION_WARNINGS -DUSE_AURA=1 -DUSE_NSS_CERTS=1 -DUSE_OZONE=1 -DNO_TCMALLOC -DFULL_SAFE_BROWSING -DSAFE_BROWSING_CSD -DSAFE_BROWSING_DB_LOCAL -DCHROMIUM_BUILD -DFIELDTRIAL_TESTING_ENABLED -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D_FORTIFY_SOURCE=2 -DCOMPONENT_BUILD -DNDEBUG -DNVALGRIND -DDYNAMIC_ANNOTATIONS_ENABLED=0 -DUSE_EGL -fno-strict-aliasing --param=ssp-buffer-size=4 -fstack-protector -Wno-builtin-macro-redefined -D__DATE__= -D__TIME__= -D__TIMESTAMP__= -funwind-tables -fPIC -pipe -pthread -m64 -march=x86-64 -Wall -Wno-unused-local-typedefs -Wno-maybe-uninitialized -Wno-missing-field-initializers -Wno-unused-parameter -fomit-frame-pointer -g0 -fvisibility=default -O2 -fno-ident -fdata-sections -ffunction-sections -std=gnu++14 -Wno-narrowing -fno-exceptions -fvisibility-inlines-hidden -D_GNU_SOURCE -DAMP_EXTRA_DIRECTORY=\"\$(libdir)/\$(PACKAGE)/extra\" -DAMP_INSTALL_SBINDIR=\"$(sbindir)\"
# XXX libboringssl is explicitly added before ssl, amp, unbound so its symbols
# get added first - parts of chromium rely on the boringssl implementation and
# crash otherwise
youtube_la_LDFLAGS=-Wl,--disable-new-dtags -R $(libdir)/$(PACKAGE)/chromium -L@CHROMIUM_BUILD_DIR@ -Wl,-fuse-ld=gold -module -avoid-version -L../../common/.libs/ -fvisibility=hidden -fno-rtti -std=c++14 -fPIC -DUSE_SYMBOLIZE -DV8_DEPRECATION_WARNINGS -DUSE_AURA=1 -DUSE_NSS_CERTS=1 -DUSE_OZONE=1 -DNO_TCMALLOC -DFULL_SAFE_BROWSING -DSAFE_BROWSING_CSD -DSAFE_BROWSING_DB_LOCAL -DCHROMIUM_BUILD -DFIELDTRIAL_TESTING_ENABLED -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D_FORTIFY_SOURCE=2 -DCOMPONENT_BUILD -DNDEBUG -DNVALGRIND -DDYNAMIC_ANNOTATIONS_ENABLED=0 -DUSE_EGL -fno-strict-aliasing --param=ssp-buffer-size=4 -fstack-protector -Wno-builtin-macro-redefined -D__DATE__= -D__TIME__= -D__TIMESTAMP__= -funwind-tables -fPIC -pipe -pthread -m64 -march=x86-64 -Wall -Wno-unused-local-typedefs -Wno-maybe-uninitialized -Wno-missing-field-initializers -Wno-unused-parameter -fomit-frame-pointer -g0 -fvisibility=default -O2 -fno-ident -fdata-sections -ffunction-sections -std=gnu++14 -Wno-narrowing -fno-exceptions -fvisibility-inlines-hidden -Wl,--start-group,${CHROMIUM_LIBS} -Wl,--end-group -Wl,--no-as-needed -ldl -lrt -lnss3 -lnssutil3 -lsmime3 -lplds4 -lplc4 -lnspr4 -lstdc++ -lbase -shared -module -lboringssl -lssl -lamp -lunbound

install-exec-local:
	mkdir -p $(DESTDIR)/$(libdir)/$(PACKAGE)/extra
	cp extra/yt.html $(DESTDIR)/$(libdir)/$(PACKAGE)/extra/
endif

youtube.pb-c.c: Makefile
	protoc-c --c_out=. youtube.proto
	protoc --python_out=../python/ampsave/tests/ youtube.proto

