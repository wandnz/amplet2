EXTRA_DIST=*.h youtube.proto extra/* README.md
#SUBDIRS= . test
SUBDIRS= .
BUILT_SOURCES=youtube.pb-c.c
CLEANFILES=youtube.pb-c.c youtube.pb-c.h

if WANT_YOUTUBE_TEST
CHROMIUM_LIBS=-lbase,-lipc,-lbindings,-lmojo_public_system_cpp,-lmojo_public_system,-lcontent,-lgpu,-lgles2_utils,-lgfx,-lskia,-lgeometry,-licui18n,-licuuc,-lrange,-lgl_wrapper,-lplatform,-lgl_init,-lui_base,-lui_data_pack,-levents_base,-lurl,-lbase_i18n,-lnet,-lprotobuf_lite,-lcrcrypto,-lboringssl,-lmedia,-lshared_memory_support,-lgfx_ipc,-lgfx_ipc_geometry,-lgfx_ipc_skia,-lcapture_base,-lgfx_ipc_color,-lcc,-lui_base_ime,-ldisplay,-ldisplay_types,-lcapture_lib,-laccessibility,-lsurface,-lurl_ipc,-lstorage_common,-lstorage_browser,-lcompositor,-ldevices,-laura,-ldisplay_util,-levents,-lppapi_host,-lppapi_proxy,-lppapi_shared,-lblink_platform,-lblink_core,-lblink_modules,-lseccomp_bpf,-lsql,-lv8,-lv8_libbase,-lv8_libplatform,-lchromium_sqlite3,-lgesture_detection,-lwtf,-ltracing,-ldiscardable_memory_client,-lstartup_tracing,-lgles2_implementation,-lmedia_gpu,-lmidi,-lsandbox_services,-lsuid_sandbox_client,-lshell_dialogs,-lnative_theme,-lgin,-lcc_animation,-lcc_paint,-ldiscardable_memory_service,-lprefs,-ldevice_gamepad,-lsnapshot,-lui_touch_selection,-laura_extra,-ldevice_event_log,-lmedia_blink,-lmojo_ime_lib,-lstub_window,-lffmpeg,-levents_ozone_layout,-lgl_in_process_context,-ldiscardable_memory_common,-lbluetooth,-lheadless,-lanimation,-lblink_common,-lcc_base,-lcc_debug,-lclient,-ldevice_base,-lembedder,-lhost,-lservice,-lblink_mojo_bindings_shared,-lblink_android_mojo_bindings_shared,-lcontent_public_common_mojo_bindings_shared,-linterfaces_shared,-lcontent_common_mojo_bindings_shared,-lviz_common,-lmedia_mojo_services,-lresource_coordinator_cpp,-lmessage_support,-lcolor_space,-lembedder,-lservice_manager_cpp_types,-lservice_manager_mojom_blink,-lservice_manager_mojom_shared,-lservice_manager_mojom,-lcodec,-lmetrics_cpp,-lgeometry_skia,-lservice_manager_cpp,-lfreetype_harfbuzz,-lprinting,-ldevice_vr_mojo_bindings_blink,-ldevice_vr_mojo_bindings,-ldevice_vr_mojo_bindings_shared,-lfingerprint,-lipc_mojom,-lipc_mojom_shared,-lsandbox,-lwm_public,-lcdm_manager,-lgfx_switches,-lembedder_switches,-lservice_manager_mojom_constants,-lwm,-lblink_controller,-lservice_manager_mojom_constants_shared,-lc++

testdir=$(libdir)/$(PACKAGE)/tests
bin_PROGRAMS=amp-youtube
amp_youtube_SOURCES=../testmain.c
amp_youtube_CFLAGS=-I../../common/
amp_youtube_LDADD=youtube.la
amp_youtube_LDFLAGS=-Wl,--disable-new-dtags -L../../common/.libs/ -rdynamic -lrt -lnss3 -lnssutil3 -lsmime3 -lplds4 -lplc4 -lnspr4 -lstdc++ -ldl -lprotobuf-c -lssl -lamp -lunbound

CXX=clang++
CC=clang
wrapperdir=$(libdir)/$(PACKAGE)/chromium
wrapper_PROGRAMS=amp-youtube-wrapper
amp_youtube_wrapper_SOURCES=wrapper.cc chromium.cc
amp_youtube_wrapper_LDADD=youtube.la
amp_youtube_wrapper_CPPFLAGS=@CHROMIUM_INCLUDES@ -I../ -I../../common/ -DV8_DEPRECATION_WARNINGS -DUSE_AURA=1 -DUSE_NSS_CERTS=1 -DUSE_OZONE=1 -DNO_TCMALLOC -DFULL_SAFE_BROWSING -DSAFE_BROWSING_CSD -DSAFE_BROWSING_DB_LOCAL -DCHROMIUM_BUILD -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -DCR_CLANG_REVISION=\"313786-1\" -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -DCOMPONENT_BUILD -DNDEBUG -DNVALGRIND -DDYNAMIC_ANNOTATIONS_ENABLED=0 -DUSE_EGL -std=gnu++14 -fno-rtti -nostdinc++ -isystem@CHROMIUM_INCLUDE_DIR@/buildtools/third_party/libc++/trunk/include -isystem@CHROMIUM_INCLUDE_DIR@/buildtools/third_party/libc++abi/trunk/include -fno-exceptions -fvisibility-inlines-hidden -D_GNU_SOURCE -DAMP_EXTRA_DIRECTORY=\"\$(libdir)/\$(PACKAGE)/extra\"
# /usr/lib/chromium-browser/ is where libffmpeg.so gets installed by the
# chromium-codecs-ffmpeg-extra package, so try to use it if available
amp_youtube_wrapper_LDFLAGS=-R /usr/lib/chromium-browser/ -R $(libdir)/$(PACKAGE)/chromium/ -L../../common/.libs/ -Wl,--start-group,${CHROMIUM_LIBS} -Wl,--end-group -L@CHROMIUM_BUILD_DIR@ -fPIC -Wl,-z,noexecstack -Wl,-z,now -Wl,-z,relro -Wl,-z,defs -lpthread -fuse-ld=lld -Wl,--icf=all -m64 -Werror -Wl,--gdb-index -Wl,-rpath-link=. -Wl,--disable-new-dtags -Wl,--export-dynamic -ldl -lpthread -lrt -lgmodule-2.0 -lgobject-2.0 -lgthread-2.0 -lglib-2.0 -lnss3 -lnssutil3 -lsmime3 -lplds4 -lplc4 -lnspr4 -lamp

test_LTLIBRARIES=youtube.la
youtube_la_SOURCES=youtube.c
nodist_youtube_la_SOURCES=youtube.pb-c.c
youtube_la_CFLAGS=-DAMP_YOUTUBE_WRAPPER_PATH=\"\$(libdir)/\$(PACKAGE)/chromium/\"
youtube_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c

INCLUDES=-I../ -I../../common/

install-exec-local:
	mkdir -p $(DESTDIR)/$(libdir)/$(PACKAGE)/extra
	cp extra/yt.html $(DESTDIR)/$(libdir)/$(PACKAGE)/extra/
endif

youtube.pb-c.c: youtube.proto
	protoc-c --c_out=. youtube.proto
	protoc --python_out=../python/ampsave/tests/ youtube.proto
