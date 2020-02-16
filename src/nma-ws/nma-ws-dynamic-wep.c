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
#include "nma-ws-dynamic-wep.h"

struct _NMAWsDynamicWep {
	NMAWs8021x parent;
};

struct _NMAWsDynamicWepClass {
	NMAWs8021xClass parent;
};

static void nma_ws_interface_init (NMAWsInterface *iface);

G_DEFINE_TYPE_WITH_CODE (NMAWsDynamicWep, nma_ws_dynamic_wep, NMA_TYPE_WS_802_1X,
                         G_IMPLEMENT_INTERFACE (NMA_TYPE_WS, nma_ws_interface_init))

static void
fill_connection (NMAWs *ws, NMConnection *connection)
{
	NMSettingWirelessSecurity *s_wireless_sec;

	nma_ws_802_1x_fill_connection (ws, connection);

	s_wireless_sec = nm_connection_get_setting_wireless_security (connection);
	g_return_if_fail (s_wireless_sec);

	g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", NULL);
}

static void
nma_ws_dynamic_wep_init (NMAWsDynamicWep *self)
{
}

static void
nma_ws_interface_init (NMAWsInterface *iface)
{
	iface->fill_connection = fill_connection;
}

NMAWsDynamicWep *
nma_ws_dynamic_wep_new (NMConnection *connection,
                        gboolean is_editor,
                        gboolean secrets_only)
{
	return g_object_new (NMA_TYPE_WS_DYNAMIC_WEP,
	                     "connection", connection,
	                     "secrets-only", secrets_only,
	                     "is-editor", is_editor,
	                     NULL);
}

static void
nma_ws_dynamic_wep_class_init (NMAWsDynamicWepClass *klass)
{
}
