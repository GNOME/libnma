// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include <ctype.h>
#include <string.h>

#include "nma-ws.h"
#include "nma-eap.h"

struct _NMAWsDynamicWEP {
	NMAWs parent;

	GtkSizeGroup *size_group;
};

static void
destroy (NMAWs *parent)
{
	NMAWsDynamicWEP *sec = (NMAWsDynamicWEP *) parent;

	if (sec->size_group)
		g_object_unref (sec->size_group);
}

static gboolean
validate (NMAWs *parent, GError **error)
{
	return nma_ws_802_1x_validate (parent, "dynamic_wep_auth_combo", error);
}

static void
add_to_size_group (NMAWs *parent, GtkSizeGroup *group)
{
	NMAWsDynamicWEP *sec = (NMAWsDynamicWEP *) parent;

	if (sec->size_group)
		g_object_unref (sec->size_group);
	sec->size_group = g_object_ref (group);

	nma_ws_802_1x_add_to_size_group (parent,
	                                 sec->size_group,
	                                 "dynamic_wep_auth_label",
	                                 "dynamic_wep_auth_combo");
}

static void
fill_connection (NMAWs *parent, NMConnection *connection)
{
	NMSettingWirelessSecurity *s_wireless_sec;

	nma_ws_802_1x_fill_connection (parent, "dynamic_wep_auth_combo", connection);

	s_wireless_sec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wireless_sec);

	g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x", NULL);
}

static void
auth_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	NMAWs *parent = NMA_WS (user_data);
	NMAWsDynamicWEP *sec = (NMAWsDynamicWEP *) parent;

	nma_ws_802_1x_auth_combo_changed (combo,
	                                  parent,
	                                  "dynamic_wep_method_vbox",
	                                  sec->size_group);
}

static void
update_secrets (NMAWs *parent, NMConnection *connection)
{
	nma_ws_802_1x_update_secrets (parent, "dynamic_wep_auth_combo", connection);
}

NMAWsDynamicWEP *
nma_ws_dynamic_wep_new (NMConnection *connection,
                        gboolean is_editor,
                        gboolean secrets_only)
{
	NMAWs *parent;
	GtkWidget *widget;

	parent = nma_ws_init (sizeof (NMAWsDynamicWEP),
	                      validate,
	                      add_to_size_group,
	                      fill_connection,
	                      update_secrets,
	                      destroy,
	                      "/org/gnome/libnma/nma-ws-dynamic-wep.ui",
	                      "dynamic_wep_notebook",
	                      NULL);
	if (!parent)
		return NULL;

	parent->adhoc_compatible = FALSE;
	parent->hotspot_compatible = FALSE;

	widget = nma_ws_802_1x_auth_combo_init (parent,
	                                        "dynamic_wep_auth_combo",
	                                        "dynamic_wep_auth_label",
	                                        (GCallback) auth_combo_changed_cb,
	                                        connection,
	                                        is_editor,
	                                        secrets_only,
	                                        NULL);
	auth_combo_changed_cb (widget, (gpointer) parent);

	return (NMAWsDynamicWEP *) parent;
}
