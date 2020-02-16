// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */
#include "nm-default.h"
#include "nma-private.h"

#include "nma-ws.h"
#include "nma-ws-private.h"
#include "nma-ws-802-1x.h"
#include "nma-ws-802-1x-private.h"
#include "nma-ws-wpa-eap.h"

struct _NMAWsWpaEap {
	NMAWs8021x parent;
};

struct _NMAWsWpaEapClass {
	NMAWs8021xClass parent;
};

static void nma_ws_interface_init (NMAWsInterface *iface);

G_DEFINE_TYPE_WITH_CODE (NMAWsWpaEap, nma_ws_wpa_eap, NMA_TYPE_WS_802_1X,
                         G_IMPLEMENT_INTERFACE (NMA_TYPE_WS, nma_ws_interface_init))

static void
fill_connection (NMAWs *ws, NMConnection *connection)
{
	NMSettingWirelessSecurity *s_wireless_sec;

	nma_ws_802_1x_fill_connection (ws, connection);

	s_wireless_sec = nm_connection_get_setting_wireless_security (connection);
	g_return_if_fail (s_wireless_sec);

	g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap", NULL);
}

static void
nma_ws_wpa_eap_init (NMAWsWpaEap *self)
{
}

static void
nma_ws_interface_init (NMAWsInterface *iface)
{
	iface->fill_connection = fill_connection;
}

NMAWsWpaEap *
nma_ws_wpa_eap_new (NMConnection *connection,
                    gboolean is_editor,
                    gboolean secrets_only,
                    const char *const*secrets_hints)
{
	return g_object_new (NMA_TYPE_WS_WPA_EAP,
	                     "connection", connection,
	                     "secrets-only", secrets_only,
	                     "is-editor", is_editor,
	                     "secrets-hints", secrets_hints,
	                     NULL);
}

static void
nma_ws_wpa_eap_class_init (NMAWsWpaEapClass *klass)
{
}
