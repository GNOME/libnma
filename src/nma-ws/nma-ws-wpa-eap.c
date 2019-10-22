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

struct _NMAWsWPAEAP {
	NMAWs parent;

	GtkSizeGroup *size_group;
};


static void
destroy (NMAWs *parent)
{
	NMAWsWPAEAP *sec = (NMAWsWPAEAP *) parent;

	if (sec->size_group)
		g_object_unref (sec->size_group);
}

static gboolean
validate (NMAWs *parent, GError **error)
{
	return nma_ws_802_1x_validate (parent, "wpa_eap_auth_combo", error);
}

static void
add_to_size_group (NMAWs *parent, GtkSizeGroup *group)
{
	NMAWsWPAEAP *sec = (NMAWsWPAEAP *) parent;

	if (sec->size_group)
		g_object_unref (sec->size_group);
	sec->size_group = g_object_ref (group);

	nma_ws_802_1x_add_to_size_group (parent,
	                                 sec->size_group,
	                                 "wpa_eap_auth_label",
	                                 "wpa_eap_auth_combo");
}

static void
fill_connection (NMAWs *parent, NMConnection *connection)
{
	NMSettingWirelessSecurity *s_wireless_sec;

	nma_ws_802_1x_fill_connection (parent, "wpa_eap_auth_combo", connection);

	s_wireless_sec = nm_connection_get_setting_wireless_security (connection);
	g_assert (s_wireless_sec);

	g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap", NULL);
}

static void
auth_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	NMAWs *parent = NMA_WS (user_data);
	NMAWsWPAEAP *sec = (NMAWsWPAEAP *) parent;

	nma_ws_802_1x_auth_combo_changed (combo,
	                                  parent,
	                                  "wpa_nma_eap_vbox",
	                                  sec->size_group);
}

static void
update_secrets (NMAWs *parent, NMConnection *connection)
{
	nma_ws_802_1x_update_secrets (parent, "wpa_eap_auth_combo", connection);
}

NMAWsWPAEAP *
nma_ws_wpa_eap_new (NMConnection *connection,
                    gboolean is_editor,
                    gboolean secrets_only,
                    const char *const*secrets_hints)
{
	NMAWs *parent;
	GtkWidget *widget;

	parent = nma_ws_init (sizeof (NMAWsWPAEAP),
	                      validate,
	                      add_to_size_group,
	                      fill_connection,
	                      update_secrets,
	                      destroy,
	                      "/org/gnome/libnma/nma-ws-wpa-eap.ui",
	                      "wpa_eap_notebook",
	                      NULL);
	if (!parent)
		return NULL;

	parent->adhoc_compatible = FALSE;
	parent->hotspot_compatible = FALSE;

	widget = nma_ws_802_1x_auth_combo_init (parent,
	                                        "wpa_eap_auth_combo",
	                                        "wpa_eap_auth_label",
	                                        (GCallback) auth_combo_changed_cb,
	                                        connection,
	                                        is_editor,
	                                        secrets_only,
	                                        secrets_hints);
	auth_combo_changed_cb (widget, parent);

	return (NMAWsWPAEAP *) parent;
}
