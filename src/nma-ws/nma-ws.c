// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nma-ws.h"
#include "nma-ws-private.h"
#include "nma-eap.h"
#include "utils.h"

G_DEFINE_INTERFACE (NMAWs, nma_ws, G_TYPE_OBJECT)

void
nma_ws_changed_cb (GtkWidget *ignored, gpointer user_data)
{
	g_signal_emit_by_name (user_data, "ws-changed");
}

gboolean
nma_ws_validate (NMAWs *self, GError **error)
{
	NMAWsInterface *iface;
	gboolean result;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	iface = NMA_WS_GET_INTERFACE (self);
	if (!iface->validate) {
		/* OWE case */
		return TRUE;
	}

	result = (*(iface->validate)) (self, error);
	if (!result && error && !*error)
		g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("Unknown error validating 802.1X security"));
	return result;
}

void
nma_ws_add_to_size_group (NMAWs *self, GtkSizeGroup *group)
{
	NMAWsInterface *iface;

	g_return_if_fail (self != NULL);
	g_return_if_fail (group != NULL);

	iface = NMA_WS_GET_INTERFACE (self);
	if (iface->add_to_size_group)
		return (*(iface->add_to_size_group)) (self, group);
}

void
nma_ws_fill_connection (NMAWs *self,
                        NMConnection *connection)
{
	NMAWsInterface *iface;

	g_return_if_fail (self != NULL);
	g_return_if_fail (connection != NULL);

	iface = NMA_WS_GET_INTERFACE (self);
	g_return_if_fail (iface->fill_connection);
	return (*(iface->fill_connection)) (self, connection);
}

void
nma_ws_update_secrets (NMAWs *self, NMConnection *connection)
{
	NMAWsInterface *iface;

	g_return_if_fail (self != NULL);
	g_return_if_fail (connection != NULL);

	iface = NMA_WS_GET_INTERFACE (self);
	if (iface->update_secrets)
		iface->update_secrets (self, connection);
}

void
nma_ws_default_init (NMAWsInterface *iface)
{
	GType iface_type = G_TYPE_FROM_INTERFACE (iface);

	g_signal_new ("ws-changed",
	              iface_type,
	              G_SIGNAL_RUN_FIRST,
	              0, NULL, NULL,
	              g_cclosure_marshal_VOID__VOID,
	              G_TYPE_NONE, 0);

	iface->adhoc_compatible = TRUE;
	iface->hotspot_compatible = TRUE;

	g_object_interface_install_property (iface,
		g_param_spec_object ("connection", "", "",
		                     NM_TYPE_CONNECTION,
		                       G_PARAM_READWRITE
		                     | G_PARAM_CONSTRUCT
		                     | G_PARAM_STATIC_STRINGS));

	g_object_interface_install_property (iface,
		g_param_spec_boolean ("secrets-only", "", "",
		                      FALSE,
		                        G_PARAM_READWRITE
		                      | G_PARAM_CONSTRUCT
		                      | G_PARAM_STATIC_STRINGS));
}

gboolean
nma_ws_adhoc_compatible (NMAWs *self)
{
	g_return_val_if_fail (self != NULL, FALSE);

	return NMA_WS_GET_INTERFACE (self)->adhoc_compatible;
}

gboolean
nma_ws_hotspot_compatible (NMAWs *self)
{
	g_return_val_if_fail (self != NULL, FALSE);

	return NMA_WS_GET_INTERFACE (self)->hotspot_compatible;
}

void
nma_ws_clear_ciphers (NMConnection *connection)
{
	NMSettingWirelessSecurity *s_wireless_sec;

	g_return_if_fail (connection != NULL);

	s_wireless_sec = nm_connection_get_setting_wireless_security (connection);
	g_return_if_fail (s_wireless_sec);

	nm_setting_wireless_security_clear_protos (s_wireless_sec);
	nm_setting_wireless_security_clear_pairwise (s_wireless_sec);
	nm_setting_wireless_security_clear_groups (s_wireless_sec);
}
