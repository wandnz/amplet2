EXTRA_DIST=*.h youtube.proto extra/yt.html
#SUBDIRS= . test
SUBDIRS= .
BUILT_SOURCES=youtube.pb-c.c
CLEANFILES=youtube.pb-c.c youtube.pb-c.h

CHROMIUM_INTERFACES_DIR=@CHROMIUM_BUILD_DIR@/obj/services/service_manager/public/interfaces/interfaces
CHROMIUM_SHARED_INTERFACES_DIR=@CHROMIUM_BUILD_DIR@/obj/services/service_manager/public/interfaces/interfaces_shared_cpp_sources
CHROMIUM_TYPES_DIR=@CHROMIUM_BUILD_DIR@/obj/mojo/common/common_custom_types
CHROMIUM_SHARED_TYPES_DIR=@CHROMIUM_BUILD_DIR@/obj/mojo/common/common_custom_types_shared_cpp_sources

CHROMIUM_OBJECTS=@CHROMIUM_BUILD_DIR@/obj/components/crash/content/browser/browser/crash_handler_host_linux.o @CHROMIUM_BUILD_DIR@/obj/components/crash/content/app/app_non_mac_win/breakpad_linux.o @CHROMIUM_BUILD_DIR@/obj/content/public/common/service_names/service_names.mojom.o @CHROMIUM_BUILD_DIR@/obj/content/public/common/service_names_shared_cpp_sources/service_names.mojom-shared.o ${CHROMIUM_INTERFACES_DIR}/connector.mojom.o ${CHROMIUM_INTERFACES_DIR}/interface_provider.mojom.o ${CHROMIUM_INTERFACES_DIR}/interface_provider_spec.mojom.o ${CHROMIUM_INTERFACES_DIR}/resolver.mojom.o ${CHROMIUM_INTERFACES_DIR}/service.mojom.o ${CHROMIUM_INTERFACES_DIR}/service_control.mojom.o ${CHROMIUM_INTERFACES_DIR}/service_factory.mojom.o ${CHROMIUM_INTERFACES_DIR}/service_manager.mojom.o ${CHROMIUM_SHARED_INTERFACES_DIR}/connector.mojom-shared.o ${CHROMIUM_SHARED_INTERFACES_DIR}/interface_provider.mojom-shared.o ${CHROMIUM_SHARED_INTERFACES_DIR}/interface_provider_spec.mojom-shared.o ${CHROMIUM_SHARED_INTERFACES_DIR}/resolver.mojom-shared.o ${CHROMIUM_SHARED_INTERFACES_DIR}/service.mojom-shared.o ${CHROMIUM_SHARED_INTERFACES_DIR}/service_control.mojom-shared.o ${CHROMIUM_SHARED_INTERFACES_DIR}/service_factory.mojom-shared.o ${CHROMIUM_SHARED_INTERFACES_DIR}/service_manager.mojom-shared.o @CHROMIUM_BUILD_DIR@/obj/services/service_manager/public/interfaces/constants_shared_cpp_sources/constants.mojom-shared.o ${CHROMIUM_SHARED_TYPES_DIR}/file.mojom-shared.o ${CHROMIUM_SHARED_TYPES_DIR}/file_path.mojom-shared.o ${CHROMIUM_SHARED_TYPES_DIR}/string16.mojom-shared.o ${CHROMIUM_SHARED_TYPES_DIR}/text_direction.mojom-shared.o ${CHROMIUM_SHARED_TYPES_DIR}/time.mojom-shared.o ${CHROMIUM_SHARED_TYPES_DIR}/unguessable_token.mojom-shared.o ${CHROMIUM_SHARED_TYPES_DIR}/values.mojom-shared.o ${CHROMIUM_SHARED_TYPES_DIR}/version.mojom-shared.o @CHROMIUM_BUILD_DIR@/obj/services/service_manager/public/interfaces/constants/constants.mojom.o ${CHROMIUM_TYPES_DIR}/file.mojom.o ${CHROMIUM_TYPES_DIR}/file_path.mojom.o ${CHROMIUM_TYPES_DIR}/string16.mojom.o ${CHROMIUM_TYPES_DIR}/text_direction.mojom.o ${CHROMIUM_TYPES_DIR}/time.mojom.o ${CHROMIUM_TYPES_DIR}/unguessable_token.mojom.o ${CHROMIUM_TYPES_DIR}/values.mojom.o ${CHROMIUM_TYPES_DIR}/version.mojom.o ${CHROMIUM_TYPES_DIR}/values_struct_traits.o @CHROMIUM_BUILD_DIR@/obj/mojo/common/struct_traits/common_custom_types_struct_traits.o @CHROMIUM_BUILD_DIR@/obj/headless/libheadless_shell_lib.a @CHROMIUM_BUILD_DIR@/obj/headless/libheadless_lib.a @CHROMIUM_BUILD_DIR@/obj/breakpad/libclient.a @CHROMIUM_BUILD_DIR@/obj/components/crash/content/app/libapp.a @CHROMIUM_BUILD_DIR@/obj/components/crash/content/app/lib.a @CHROMIUM_BUILD_DIR@/obj/base/libbase_static.a @CHROMIUM_BUILD_DIR@/obj/components/crash/core/common/libcrash_keys.a @CHROMIUM_BUILD_DIR@/obj/components/security_state/content/libcontent.a @CHROMIUM_BUILD_DIR@/obj/components/security_state/core/libcore.a @CHROMIUM_BUILD_DIR@/obj/services/service_manager/public/cpp/libsources.a

CHROMIUM_LIBS=-lbase,-lipc,-lbindings,-lmojo_public_system_cpp,-lmojo_public_system,-lcontent,-lgpu,-lgles2_utils,-lgfx,-lskia,-lgeometry,-licui18n,-licuuc,-lrange,-lgl_wrapper,-lplatform,-lgl_init,-lui_base,-lui_data_pack,-levents_base,-lurl,-lbase_i18n,-lnet,-lprotobuf_lite,-lcrcrypto,-lboringssl,-lmedia,-lshared_memory_support,-lmojo_common_lib,-lgfx_ipc,-lgfx_ipc_geometry,-lgfx_ipc_skia,-lcapture_base,-lgfx_ipc_color,-lcc,-lui_base_ime,-ldisplay,-ldisplay_types,-lcapture_lib,-lcc_ipc,-lcc_surfaces,-laccessibility,-lsurface,-lurl_ipc,-lmojo_system_impl,-lstorage_common,-lstorage_browser,-lcompositor,-ldevices,-laura,-lozone,-lozone_base,-ldisplay_util,-levents,-lgl,-lppapi_host,-lppapi_proxy,-lppapi_shared,-lblink_platform,-lblink_web,-lblink_core,-lblink_modules,-lseccomp_bpf,-lsql,-lv8,-lv8_libbase,-lv8_libplatform,-lchromium_sqlite3,-lgesture_detection,-lwtf,-ltracing,-ldiscardable_memory_client,-lstartup_tracing,-lgles2_implementation,-lmedia_gpu,-lmidi,-lsandbox_services,-lsuid_sandbox_client,-levents_ipc,-lshell_dialogs,-lnative_theme,-lgin,-ldisplay_compositor,-lcc_animation,-lcc_paint,-ldiscardable_memory_service,-lprefs,-ldevice_battery,-ldevice_gamepad,-lgeneric_sensor,-lcpp,-lgeolocation,-lpower_save_blocker,-lsensors,-ldevice_vibration,-ldevice_vr,-lsnapshot,-lui_touch_selection,-laura_extra,-lcc_blink,-ldevice_event_log,-lmedia_blink,-ljs,-lmojo_ime_lib,-lstub_window,-lffmpeg,-levents_ozone_layout,-lgl_in_process_context,-ldiscardable_memory_common,-lbluetooth

testdir=$(libdir)/$(PACKAGE)/tests
bin_PROGRAMS=amp-youtube
amp_youtube_SOURCES=../testmain.c
amp_youtube_CPPFLAGS=-I../../common/
amp_youtube_LDADD=youtube.la
amp_youtube_LDFLAGS=-R $(libdir)/$(PACKAGE)/chromium -L@CHROMIUM_BUILD_DIR@ -Wl,--no-as-needed -L../../common/ ${CHROMIUM_OBJECTS} -Wl,--as-needed -Wl,--start-group,${CHROMIUM_LIBS} -Wl,--end-group -Wl,--no-as-needed -ldl -lrt -lnss3 -lnssutil3 -lsmime3 -lplds4 -lplc4 -lnspr4 -lpthread -lprotobuf-c -lamp -lwandevent -lunbound -lstdc++

test_LTLIBRARIES=youtube.la
youtube_la_SOURCES=youtube.c chromium.cc
nodist_youtube_la_SOURCES=youtube.pb-c.c
youtube_la_CPPFLAGS=@CHROMIUM_INCLUDE_DIR@ -I../ -I../../common/ -fPIC -std=c++11 -DV8_DEPRECATION_WARNINGS -DUI_COMPOSITOR_IMAGE_TRANSPORT -DUSE_AURA=1 -DUSE_NSS_CERTS=1 -DUSE_OZONE=1 -DDISABLE_NACL -DFULL_SAFE_BROWSING -DSAFE_BROWSING_CSD -DSAFE_BROWSING_DB_LOCAL -DCHROMIUM_BUILD -DENABLE_MEDIA_ROUTER=1 -DFIELDTRIAL_TESTING_ENABLED -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D_FORTIFY_SOURCE=2 -DCOMPONENT_BUILD -DNDEBUG -DNVALGRIND -DDYNAMIC_ANNOTATIONS_ENABLED=0 -DHEADLESS_IMPLEMENTATION -DHEADLESS_USE_EMBEDDED_RESOURCES -DUSE_EGL -DU_USING_ICU_NAMESPACE=0 -DU_ENABLE_DYLOAD=0 -DICU_UTIL_DATA_IMPL=ICU_UTIL_DATA_STATIC -DSK_IGNORE_DW_GRAY_FIX -DSK_IGNORE_DIRECTWRITE_GASP_FIX -DSK_IGNORE_LINEONLY_AA_CONVEX_PATH_OPTS -DSKIA_DLL -DGR_GL_IGNORE_ES3_MSAA=0 -DSK_SUPPORT_GPU=1 -DMESA_EGL_NO_X11_HEADERS -DGOOGLE_PROTOBUF_NO_RTTI -DGOOGLE_PROTOBUF_NO_STATIC_INITIALIZER -DHAVE_PTHREAD -DPROTOBUF_USE_DLLS -DBORINGSSL_SHARED_LIBRARY -DUSING_V8_SHARED -DAMP_EXTRA_DIRECTORY=\"\$(libdir)/\$(PACKAGE)/extra\" -DAMP_INSTALL_SBINDIR=\"$(sbindir)\"
#youtube_la_LIBADD=libstatics.la
#youtube_la_LDFLAGS=-L@CHROMIUM_BUILD_DIR@ -module -avoid-version -L../../common/ ${CHROMIUM_OBJECTS} -Wl,--as-needed, -Wl,--start-group,${CHROMIUM_LIBS} -Wl,--end-group -Wl,--no-as-needed -ldl -lrt -lnss3 -lnssutil3 -lsmime3 -lplds4 -lplc4 -lnspr4 -lpthread -lprotobuf-c -lamp -lwandevent
youtube_la_LDFLAGS=-R $(libdir)/$(PACKAGE)/chromium -L@CHROMIUM_BUILD_DIR@ -module -avoid-version -Wl,--no-as-needed -L../../common/ ${CHROMIUM_OBJECTS} -Wl,--as-needed, -Wl,--start-group,${CHROMIUM_LIBS} -Wl,--end-group -Wl,--no-as-needed -ldl -lrt -lnss3 -lnssutil3 -lsmime3 -lplds4 -lplc4 -lnspr4 -lpthread -lprotobuf-c -lamp -lwandevent -lstdc++

# XXX can we combine all object files and static libraries into static library?
#libstaticsdir=$(libdir)/$(PACKAGE)/
#libstatics_LTLIBRARIES=libstatics.la
#nodist_libstatics_la_SOURCES=${CHROMIUM_OBJECTS}

# XXX do i need headless shell lib?

youtube.pb-c.c: Makefile
	protoc-c --c_out=. youtube.proto
	protoc --python_out=../python/ampsave/tests/ youtube.proto

install-exec-local:
	mkdir -p $(DESTDIR)/$(libdir)/$(PACKAGE)/extra
	cp extra/yt.html $(DESTDIR)/$(libdir)/$(PACKAGE)/extra/
