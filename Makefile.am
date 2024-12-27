include $(GLIB_MAKEFILE)
-include $(INTROSPECTION_MAKEFILE)
-include $(VAPIGEN_MAKEFILE)
include $(top_srcdir)/gtk-doc.make

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AUTOMAKE_OPTIONS = subdir-objects foreign

BUILT_SOURCES =

bin_PROGRAMS =

lib_LTLIBRARIES =

noinst_LTLIBRARIES =

check_PROGRAMS_norun =

noinst_PROGRAMS = $(check_PROGRAMS_norun)

check_PROGRAMS =

check_programs =

check_local =

TESTS =

DISTCLEANFILES =

DISTCHECK_CONFIGURE_FLAGS = \
	--disable-dependency-tracking \
	--enable-gtk-doc \
	--enable-introspection \
	--enable-more-warnings=error \
	--with-gcr

man_MANS =

pkgconfig_DATA =

pkgconfigdir = $(libdir)/pkgconfig

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)
BUILT_SOURCES += $(gir_DATA)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)
BUILT_SOURCES += $(typelib_DATA)

INTROSPECTION_GIRS =

if ENABLE_VAPIGEN
vapidir = $(datadir)/vala/vapi
VAPIGEN_VAPIS =
vapi_DATA = $(VAPIGEN_VAPIS) $(VAPIGEN_VAPIS:.vapi=.deps)
endif

SUBDIRS = \
	. \
	po

dflt_cppflags = -std=gnu99 \
	-DNMA_COMPILATION

###############################################################################

shared_files = \
	shared/nm-utils/nm-shared-utils.c \
	shared/nm-utils/nm-shared-utils.h \
	$(NULL)

noinst_LTLIBRARIES += src/utils/libutils-libnm.la

src_utils_libutils_libnm_la_CPPFLAGS = \
	$(dflt_cppflags) \
	"-I$(srcdir)/shared" \
	$(GTK3_CFLAGS) \
	$(LIBNM_CFLAGS)

src_utils_libutils_libnm_la_SOURCES = \
	$(shared_files) \
	src/utils/utils.c \
	src/utils/utils.h

src_utils_libutils_libnm_la_LIBADD = \
	$(GTK3_LIBS) \
	$(LIBNM_LIBS)

if WITH_LIBNMA_GTK4

noinst_LTLIBRARIES += src/utils/libutils-libnm-gtk4.la

src_utils_libutils_libnm_gtk4_la_CPPFLAGS = \
	$(dflt_cppflags) \
	"-I$(srcdir)/shared" \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS)

src_utils_libutils_libnm_gtk4_la_SOURCES = \
	$(shared_files) \
	src/utils/utils.c \
	src/utils/utils.h

src_utils_libutils_libnm_gtk4_la_LIBADD = \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS)

endif

check_programs += src/utils/tests/test-utils

src_utils_tests_test_utils_SOURCES = src/utils/tests/test-utils.c

src_utils_tests_test_utils_CPPFLAGS = \
	$(dflt_cppflags) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src/utils" \
	$(GTK3_CFLAGS) \
	$(LIBNM_CFLAGS)

src_utils_tests_test_utils_LDADD = \
	src/utils/libutils-libnm.la \
	$(GTK3_LIBS) \
	$(LIBNM_LIBS)

EXTRA_DIST += src/utils/meson.build

###############################################################################

src/nma-resources.h: src/nma.gresource.xml
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/src --generate-header --internal

src/nma-resources.c: src/nma.gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --sourcedir=$(srcdir)/src --generate-dependencies $(srcdir)/src/nma.gresource.xml)
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/src --generate-source --internal

src/libnma-gtk4/nma-resources.c: src/nma.gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --generate-dependencies $(srcdir)/src/nma.gresource.xml |sed "s,^,$(builddir)/src/libnma-gtk4/,")
	@mkdir -p $(builddir)/src/libnma-gtk4 $(builddir)/src/libnma-gtk4/nma-ws
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/src/libnma-gtk4 --sourcedir=$(builddir)/src/libnma-gtk4 --generate-source --internal

src/libnma-gtk4/%.ui: src/%.ui
	@mkdir -p $(builddir)/src/libnma-gtk4 $(builddir)/src/libnma-gtk4/nma-ws
	gtk4-builder-tool simplify --3to4 $< |grep -v can.default >$@

# Include Gtk4 GtkBuilder files in release tarball.
# This way we can ship files that have been tested to be known good.
# Running gtk4-builder-tool at build time is not recommended:
# https://gitlab.gnome.org/GNOME/gtk/-/merge_requests/4415
EXTRA_DIST += \
	src/libnma-gtk4/nma-mobile-wizard.ui \
	src/libnma-gtk4/nma-bar-code-widget.ui \
	src/libnma-gtk4/nma-ws/nma-ws-leap.ui \
	src/libnma-gtk4/nma-ws/nma-eap-leap.ui \
	src/libnma-gtk4/nma-ws/nma-ws-wpa-psk.ui \
	src/libnma-gtk4/nma-ws/nma-eap-simple.ui \
	src/libnma-gtk4/nma-ws/nma-ws-wep-key.ui \
	src/libnma-gtk4/nma-ws/nma-eap-tls.ui \
	src/libnma-gtk4/nma-ws/nma-ws-802-1x.ui \
	src/libnma-gtk4/nma-ws/nma-eap-fast.ui \
	src/libnma-gtk4/nma-ws/nma-eap-peap.ui \
	src/libnma-gtk4/nma-ws/nma-eap-ttls.ui \
	src/libnma-gtk4/nma-ws/nma-ws-sae.ui \
	src/libnma-gtk4/nma-cert-chooser.ui \
	src/libnma-gtk4/nma-pkcs11-token-login-dialog.ui \
	src/libnma-gtk4/nma-vpn-password-dialog.ui \
	src/libnma-gtk4/nma-pkcs11-cert-chooser-dialog.ui \
	src/libnma-gtk4/nma-wifi-dialog.ui

CLEANFILES += \
	$(libnma_h_priv_gen) \
	$(libnma_c_gen) \
	$(libnma_gtk4_c_gen)

libnma_h_priv_gen = \
	src/nma-resources.h

libnma_c_gen = \
	src/nma-resources.c

libnma_gtk4_c_gen = \
	src/libnma-gtk4/nma-resources.c

libnma_h_pub = \
	src/nma.h \
	src/nma-version.h \
	src/nma-wifi-dialog.h \
	src/nma-mobile-wizard.h \
	src/nma-mobile-providers.h \
	src/nma-vpn-password-dialog.h \
	src/nma-ui-utils.h \
	src/nma-cert-chooser.h \
	src/nma-bar-code-widget.h \
	src/nma-bar-code.h \
	\
	src/nma-ws/nma-ws-802-1x.h \
	src/nma-ws/nma-ws-dynamic-wep.h \
	src/nma-ws/nma-ws.h \
	src/nma-ws/nma-ws-leap.h \
	src/nma-ws/nma-ws-owe.h \
	src/nma-ws/nma-ws-sae.h \
	src/nma-ws/nma-ws-wep-key.h \
	src/nma-ws/nma-ws-wpa-eap.h \
	src/nma-ws/nma-ws-wpa-psk.h

libnma_c_real = \
	src/nma-wifi-dialog.c \
	src/nma-mobile-wizard.c \
	src/nma-mobile-providers.c \
	src/nma-vpn-password-dialog.c \
	src/nma-ui-utils.c \
	src/init.c \
	src/nma-cert-chooser.c \
	src/nma-cert-chooser-button.c \
	src/nma-bar-code-widget.c \
	src/nma-bar-code.c \
	\
	src/nma-ws/nma-eap-fast.c \
	src/nma-ws/nma-eap-leap.c \
	src/nma-ws/nma-eap-peap.c \
	src/nma-ws/nma-eap-simple.c \
	src/nma-ws/nma-eap-tls.c \
	src/nma-ws/nma-eap-ttls.c \
	src/nma-ws/nma-eap.c \
	src/nma-ws/nma-ws-802-1x.c \
	src/nma-ws/nma-ws-dynamic-wep.c \
	src/nma-ws/nma-ws-helpers.c \
	src/nma-ws/nma-ws-leap.c \
	src/nma-ws/nma-ws-owe.c \
	src/nma-ws/nma-ws-sae.c \
	src/nma-ws/nma-ws-wep-key.c \
	src/nma-ws/nma-ws-wpa-eap.c \
	src/nma-ws/nma-ws-wpa-psk.c \
	src/nma-ws/nma-ws.c \
	$(NULL)

EXTRA_DIST += \
	src/qrcodegen.c \
	src/qrcodegen.h

libnma_h_priv_real = \
	src/nma-private.h \
	src/nma-ws/nma-eap-fast.h \
	src/nma-ws/nma-eap-leap.h \
	src/nma-ws/nma-eap-peap.h \
	src/nma-ws/nma-eap-simple.h \
	src/nma-ws/nma-eap-tls.h \
	src/nma-ws/nma-eap-ttls.h \
	src/nma-ws/nma-eap.h \
	src/nma-cert-chooser-button.h \
	src/nma-ws/nma-ws-802-1x-private.h \
	src/nma-ws/nma-ws-helpers.h \
	src/nma-ws/nma-ws-private.h \
	$(NULL)

libnma_h_priv_gcr = \
	src/nma-pkcs11-token-login-dialog.h \
	src/nma-pkcs11-cert-chooser-dialog.h

libnma_c_gcr = \
	src/nma-pkcs11-token-login-dialog.c \
	src/nma-pkcs11-cert-chooser-dialog.c

src_libnmadir = $(includedir)/libnma

src_libnma_HEADERS = \
	$(libnma_h_pub)

lib_LTLIBRARIES += src/libnma.la

src_libnma_la_SOURCES = \
	$(libnma_h_priv_real) \
	$(libnma_c_real)

if WITH_GCR
src_libnma_la_SOURCES += \
	$(libnma_h_priv_gcr) \
	$(libnma_c_gcr)
endif

nodist_src_libnma_la_SOURCES = \
	$(libnma_h_priv_gen) \
	$(libnma_c_gen)

src_libnma_la_CFLAGS = \
	$(dflt_cppflags) \
	-DICONDIR=\""$(datadir)/icons"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DDATADIR=\""$(datadir)"\" \
	-DAUTOSTARTDIR=\""$(sysconfdir)/xdg/autostart"\" \
	-DNMALOCALEDIR=\"$(datadir)/locale\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	"-I$(srcdir)/shared" \
	"-I$(srcdir)/src/utils" \
	"-I$(srcdir)/src/nma-ws" \
	"-I$(srcdir)/src" \
	-Isrc \
	$(GTK3_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(GCR_CFLAGS)

src_libnma_la_LIBADD = \
	src/utils/libutils-libnm.la \
	$(GTK3_LIBS) \
	$(LIBNM_LIBS) \
	$(GCR_LIBS)

EXTRA_src_libnma_la_DEPENDENCIES = src/libnma.ver

src_libnma_la_LDFLAGS = \
	-Wl,-no-undefined \
	-Wl,--version-script=$(srcdir)/src/libnma.ver


pkgconfig_DATA += src/libnma.pc

if HAVE_INTROSPECTION
src/NMA-1.0.gir: src/libnma.la
src_NMA_1_0_gir_INCLUDES = NM-1.0 Gtk-3.0
src_NMA_1_0_gir_EXPORT_PACKAGES = libnma
src_NMA_1_0_gir_CFLAGS = $(src_libnma_la_CFLAGS)
src_NMA_1_0_gir_LIBS = src/libnma.la
src_NMA_1_0_gir_C_INCLUDES = nma.h
src_NMA_1_0_gir_FILES = \
	$(libnma_h_pub) \
	$(libnma_c_real)
if WITH_GCR
src_NMA_1_0_gir_FILES += \
	$(libnma_c_gcr)
endif
src_NMA_1_0_gir_SCANNERFLAGS = --warn-all --identifier-prefix=NMA --symbol-prefix=nma
INTROSPECTION_GIRS += src/NMA-1.0.gir
endif

if ENABLE_VAPIGEN
VAPIGEN_VAPIS += src/libnma.vapi
src_libnma_vapi_FILES = $(builddir)/src/NMA-1.0.gir
src_libnma_vapi_DEPS = libnm gtk+-3.0 gio-2.0
src/libnma.vapi: $(src_libnma_vapi_FILES) $(srcdir)/src/libnma.deps
endif

check_PROGRAMS_norun += src/tests/mobile-wizard

src_tests_mobile_wizard_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK3_CFLAGS) \
	$(LIBNM_CFLAGS) \
	-DNMALOCALEDIR=\"$(datadir)/locale\" \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	-Isrc

src_tests_mobile_wizard_LDADD = \
	$(GLIB_LIBS) \
	$(GTK3_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma.la

check_PROGRAMS_norun += src/tests/vpn-password-dialog

src_tests_vpn_password_dialog_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK3_CFLAGS) \
	$(LIBNM_CFLAGS) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	-Isrc

src_tests_vpn_password_dialog_LDADD = \
	$(GLIB_LIBS) \
	$(GTK3_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma.la

check_PROGRAMS_norun += src/tests/wifi-dialog

src_tests_wifi_dialog_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK3_CFLAGS) \
	$(LIBNM_CFLAGS) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	-Isrc

src_tests_wifi_dialog_LDADD = \
	$(GLIB_LIBS) \
	$(GTK3_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma.la

check_PROGRAMS_norun += src/tests/ws

src_tests_ws_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK3_CFLAGS) \
	$(LIBNM_CFLAGS) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	"-I$(srcdir)/src/nma-ws" \
	-Isrc

src_tests_ws_LDADD = \
	$(GLIB_LIBS) \
	$(GTK3_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma.la

check_PROGRAMS_norun += src/tests/wifi-dialog-secrets

src_tests_wifi_dialog_secrets_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK3_CFLAGS) \
	$(LIBNM_CFLAGS) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	-Isrc

src_tests_wifi_dialog_secrets_LDADD = \
	$(GLIB_LIBS) \
	$(GTK3_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma.la

check_PROGRAMS_norun += src/tests/run-vpn

src_tests_run_vpn_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK3_CFLAGS) \
	$(LIBNM_CFLAGS) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	-Isrc

src_tests_run_vpn_LDADD = \
	$(GLIB_LIBS) \
	$(GTK3_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma.la

check_PROGRAMS_norun += src/tests/cert-chooser

src_tests_cert_chooser_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK3_CFLAGS) \
	$(LIBNM_CFLAGS) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	-Isrc

src_tests_cert_chooser_LDADD = \
	$(GLIB_LIBS) \
	$(GTK3_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma.la

check_PROGRAMS_norun += src/tests/bar-code

src_tests_bar_code_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK3_CFLAGS) \
	$(LIBNM_CFLAGS) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	-Isrc

src_tests_bar_code_LDADD = \
	$(GLIB_LIBS) \
	$(GTK3_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma.la

if WITH_LIBNMA_GTK4

lib_LTLIBRARIES += src/libnma-gtk4.la

src_libnma_gtk4_la_SOURCES = \
	$(libnma_h_priv_real) \
	$(libnma_c_real)

if WITH_GCR
src_libnma_gtk4_la_SOURCES += \
	$(libnma_h_priv_gcr) \
	$(libnma_c_gcr)
endif

nodist_src_libnma_gtk4_la_SOURCES = \
	$(libnma_h_priv_gen) \
	$(libnma_gtk4_c_gen)

src_libnma_gtk4_la_CFLAGS = \
	$(dflt_cppflags) \
	-DICONDIR=\""$(datadir)/icons"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DDATADIR=\""$(datadir)"\" \
	-DAUTOSTARTDIR=\""$(sysconfdir)/xdg/autostart"\" \
	-DNMALOCALEDIR=\"$(datadir)/locale\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	"-I$(srcdir)/shared" \
	"-I$(srcdir)/src/utils" \
	"-I$(srcdir)/src/nma-ws" \
	"-I$(srcdir)/src" \
	-Isrc \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(GCR_CFLAGS)

src_libnma_gtk4_la_LIBADD = \
	src/utils/libutils-libnm-gtk4.la \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	$(GCR_LIBS)

EXTRA_src_libnma_gtk4_la_DEPENDENCIES = src/libnma.ver

src_libnma_gtk4_la_LDFLAGS = \
	-Wl,-no-undefined \
	-Wl,--version-script=$(srcdir)/src/libnma.ver


pkgconfig_DATA += src/libnma-gtk4.pc

if HAVE_INTROSPECTION
src/NMA4-1.0.gir: src/libnma-gtk4.la
src_NMA4_1_0_gir_INCLUDES = NM-1.0 Gtk-4.0
src_NMA4_1_0_gir_EXPORT_PACKAGES = libnma-gtk4
src_NMA4_1_0_gir_CFLAGS = $(src_libnma_gtk4_la_CFLAGS)
src_NMA4_1_0_gir_LIBS = src/libnma-gtk4.la
src_NMA4_1_0_gir_C_INCLUDES = nma.h
src_NMA4_1_0_gir_FILES = \
	$(libnma_h_pub) \
	$(libnma_c_real)
if WITH_GCR
src_NMA4_1_0_gir_FILES += \
	$(libnma_c_gcr)
endif
src_NMA4_1_0_gir_SCANNERFLAGS = --warn-all --identifier-prefix=NMA --symbol-prefix=nma
INTROSPECTION_GIRS += src/NMA4-1.0.gir
endif

if ENABLE_VAPIGEN
VAPIGEN_VAPIS += src/libnma-gtk4.vapi
src_libnma_gtk4_vapi_FILES = $(builddir)/src/NMA4-1.0.gir
src_libnma_gtk4_vapi_DEPS = libnm gtk4 gio-2.0
src/libnma-gtk4.vapi: $(src_libnma_gtk4_vapi_FILES) $(srcdir)/src/libnma-gtk4.deps
endif

check_PROGRAMS_norun += src/tests/mobile-wizard-gtk4

src_tests_mobile_wizard_gtk4_SOURCES = \
	src/tests/mobile-wizard.c

src_tests_mobile_wizard_gtk4_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	-DNMALOCALEDIR=\"$(datadir)/locale\" \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	-Isrc

src_tests_mobile_wizard_gtk4_LDADD = \
	$(GLIB_LIBS) \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma-gtk4.la

check_PROGRAMS_norun += src/tests/vpn-password-dialog-gtk4

src_tests_vpn_password_dialog_gtk4_SOURCES = \
	src/tests/vpn-password-dialog.c

src_tests_vpn_password_dialog_gtk4_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	-Isrc

src_tests_vpn_password_dialog_gtk4_LDADD = \
	$(GLIB_LIBS) \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma-gtk4.la

check_PROGRAMS_norun += src/tests/wifi-dialog-gtk4

src_tests_wifi_dialog_gtk4_SOURCES = \
	src/tests/wifi-dialog.c

src_tests_wifi_dialog_gtk4_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	-Isrc

src_tests_wifi_dialog_gtk4_LDADD = \
	$(GLIB_LIBS) \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma-gtk4.la

check_PROGRAMS_norun += src/tests/ws-gtk4

src_tests_ws_gtk4_SOURCES = \
	src/tests/ws.c

src_tests_ws_gtk4_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	"-I$(srcdir)/src/nma-ws" \
	-Isrc

src_tests_ws_gtk4_LDADD = \
	$(GLIB_LIBS) \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma-gtk4.la

check_PROGRAMS_norun += src/tests/wifi-dialog-secrets-gtk4

src_tests_wifi_dialog_secrets_gtk4_SOURCES = \
	src/tests/wifi-dialog-secrets.c

src_tests_wifi_dialog_secrets_gtk4_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	-Isrc

src_tests_wifi_dialog_secrets_gtk4_LDADD = \
	$(GLIB_LIBS) \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma-gtk4.la

check_PROGRAMS_norun += src/tests/run-vpn-gtk4

src_tests_run_vpn_gtk4_SOURCES = \
	src/tests/run-vpn.c

src_tests_run_vpn_gtk4_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	-Isrc

src_tests_run_vpn_gtk4_LDADD = \
	$(GLIB_LIBS) \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma-gtk4.la

check_PROGRAMS_norun += src/tests/cert-chooser-gtk4

src_tests_cert_chooser_gtk4_SOURCES = \
	src/tests/cert-chooser.c

src_tests_cert_chooser_gtk4_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	-Isrc

src_tests_cert_chooser_gtk4_LDADD = \
	$(GLIB_LIBS) \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma-gtk4.la

check_PROGRAMS_norun += src/tests/bar-code-gtk4

src_tests_bar_code_gtk4_SOURCES = \
	src/tests/bar-code.c

src_tests_bar_code_gtk4_CPPFLAGS = \
	$(dflt_cppflags) \
	$(GLIB_CFLAGS) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	"-I$(srcdir)/shared/" \
	"-I$(srcdir)/src" \
	-Isrc

src_tests_bar_code_gtk4_LDADD = \
	$(GLIB_LIBS) \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	src/libnma-gtk4.la

endif

EXTRA_DIST += \
	src/nma-version.h.in \
	src/libnma.pc.in \
	src/libnma-gtk4.pc.in \
	src/libnma.ver \
	src/libnma-gtk4.deps \
	src/libnma.deps \
	src/nma-mobile-wizard.ui \
	src/nma-bar-code-widget.ui \
	src/nma-cert-chooser.ui \
	src/nma-pkcs11-token-login-dialog.ui \
	src/nma-pkcs11-cert-chooser-dialog.ui \
	src/nma-vpn-password-dialog.ui \
	src/nma-wifi-dialog.ui \
	src/nma.gresource.xml \
	src/meson.build \
	src/tests/meson.build \
	\
	src/nma-ws/meson.build \
	src/nma-ws/nma-eap-fast.ui \
	src/nma-ws/nma-eap-leap.ui \
	src/nma-ws/nma-eap-peap.ui \
	src/nma-ws/nma-eap-simple.ui \
	src/nma-ws/nma-eap-tls.ui \
	src/nma-ws/nma-eap-ttls.ui \
	src/nma-ws/nma-ws-802-1x.ui \
	src/nma-ws/nma-ws-leap.ui \
	src/nma-ws/nma-ws-sae.ui \
	src/nma-ws/nma-ws-wep-key.ui \
	src/nma-ws/nma-ws-wpa-psk.ui \
	$(NULL)

###############################################################################

EXTRA_DIST += \
	shared/nm-utils/gsystem-local-alloc.h \
	shared/nm-utils/nm-compat.c \
	shared/nm-utils/nm-compat.h \
	shared/nm-utils/nm-glib.h \
	shared/nm-utils/nm-macros-internal.h \
	shared/nm-utils/nm-shared-utils.c \
	shared/nm-utils/nm-shared-utils.h \
	shared/nm-utils/nm-test-utils.h \
	shared/nm-utils/nm-vpn-editor-plugin-call.h \
	shared/nm-default.h \
	shared/nm-libnm-compat.h \
	shared/meson.build \
	$(NULL)

###############################################################################

DOC_MODULE = libnma

DOC_SOURCE_DIR = $(top_srcdir)/src

SCAN_OPTIONS=--rebuild-types --rebuild-sections

DOC_MAIN_SGML_FILE = libnma-docs.xml

GTKDOC_LIBS = src/libnma.la

scan-build.stamp: $(GTKDOC_LIBS)

HFILE_GLOB = $(top_srcdir)/src/*.h

CFILE_GLOB = $(top_srcdir)/src/*.c

IGNORE_HFILES = \
	nma-resources.h \
	nma-version.h \
	nma-private.h \
	nma-pkcs11-token-login-dialog.h \
	nma-pkcs11-cert-chooser-dialog.h \
	nma-cert-chooser-button.h \
	nma-eap.h

mkdb_ignore_c_files = \
	nma-resources.c \
	nma-pkcs11-token-login-dialog.c \
	nma-pkcs11-cert-chooser-dialog.c \
	nma-cert-chooser-button.c

MKDB_OPTIONS = --ignore-files "$(IGNORE_HFILES) $(mkdb_ignore_c_files)"

###############################################################################

# org.gnome.nm-applet.gschema.xml belongs to nm-applet.
# Kept here for now to avoid breaking on upgrades.
gsettings_SCHEMAS = \
	org.gnome.nm-applet.gschema.xml \
	org.gnome.nm-applet.eap.gschema.xml
@GSETTINGS_RULES@

check_PROGRAMS += $(check_programs)

check-local: $(check_local)

TESTS += $(check_programs)

EXTRA_DIST += \
	NEWS \
	linker-script-binary.ver \
	CONTRIBUTING \
	COPYING.LGPL \
	autogen.sh \
	meson.build \
	meson_options.txt \
	config.h.meson \
	gtkdocentities.ent.in \
	\
	po/meson.build

CLEANFILES += \
	$(INTROSPECTION_GIRS) \
	$(typelib_DATA) \
	$(VAPIGEN_VAPIS) \
	\
	$(BUILT_SOURCES)
