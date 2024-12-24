// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2007 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <string.h>

#include "nma-ws.h"
#include "nma-ws-private.h"
#include "nma-ws-sae.h"
#include "nma-ws-helpers.h"
#include "nma-ui-utils.h"
#include "utils.h"

struct _NMAWsSae {
	GtkGrid parent;

	GtkWidget *psk_entry;
	GtkWidget *sae_label;

	NMConnection *connection;
	gboolean secrets_only;
};

struct _NMAWsSaeClass {
	GtkGridClass parent;
};

static void nma_ws_interface_init (NMAWsInterface *iface);

G_DEFINE_TYPE_WITH_CODE (NMAWsSae, nma_ws_sae, GTK_TYPE_GRID,
                         G_IMPLEMENT_INTERFACE (NMA_TYPE_WS, nma_ws_interface_init))

enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_SECRETS_ONLY,
	PROP_LAST
};

static gboolean
validate (NMAWs *ws, GError **error)
{
	NMAWsSae *self = NMA_WS_SAE (ws);
	NMSettingSecretFlags secret_flags;
	const char *key;

	secret_flags = nma_utils_menu_to_secret_flags (self->psk_entry);
	key = gtk_editable_get_text (GTK_EDITABLE (self->psk_entry));

        if (   secret_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED
            || secret_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED) {
		/* All good. */
	} else if (key == NULL || key[0] == '\0') {
		widget_set_error (self->psk_entry);
		g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("missing password"));
		return FALSE;
	}
	widget_unset_error (self->psk_entry);

	return TRUE;
}

static void
add_to_size_group (NMAWs *ws, GtkSizeGroup *group)
{
	NMAWsSae *self = NMA_WS_SAE (ws);

	gtk_size_group_add_widget (group, self->sae_label);
}

static void
fill_connection (NMAWs *ws, NMConnection *connection)
{
	NMAWsSae *self = NMA_WS_SAE (ws);
	const char *key;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;
	NMSettingSecretFlags secret_flags;
	const char *mode;
	gboolean is_adhoc = FALSE;

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_return_if_fail (s_wireless);

	mode = nm_setting_wireless_get_mode (s_wireless);
	if (mode && !strcmp (mode, "adhoc"))
		is_adhoc = TRUE;

	/* Blow away the old security setting by adding a clear one */
	s_wireless_sec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, (NMSetting *) s_wireless_sec);

	key = gtk_editable_get_text (GTK_EDITABLE (self->psk_entry));
	g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_PSK, key, NULL);

	/* Save PSK_FLAGS to the connection */
	secret_flags = nma_utils_menu_to_secret_flags (self->psk_entry);
	nm_setting_set_secret_flags (NM_SETTING (s_wireless_sec), NM_SETTING_WIRELESS_SECURITY_PSK,
	                             secret_flags, NULL);

	/* Update secret flags and popup when editing the connection */
	if (!self->secrets_only) {
		nma_utils_update_password_storage (self->psk_entry, secret_flags,
		                                   NM_SETTING (s_wireless_sec),
		                                   NM_SETTING_WIRELESS_SECURITY_PSK);
	}

	nma_ws_clear_ciphers (connection);
	if (is_adhoc) {
		/* Ad-Hoc settings as specified by the supplicant */
		g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "sae", NULL);
		nm_setting_wireless_security_add_proto (s_wireless_sec, "rsn");
		nm_setting_wireless_security_add_pairwise (s_wireless_sec, "ccmp");
		nm_setting_wireless_security_add_group (s_wireless_sec, "ccmp");
	} else {
		g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "sae", NULL);

		/* Just leave ciphers and protocol empty, the supplicant will
		 * figure that out magically based on the AP IEs and card capabilities.
		 */
	}
}

static void
update_secrets (NMAWs *ws, NMConnection *connection)
{
	NMAWsSae *self = NMA_WS_SAE (ws);

	nma_ws_helper_fill_secret_entry (connection,
	                                 GTK_EDITABLE (self->psk_entry),
	                                 NM_TYPE_SETTING_WIRELESS_SECURITY,
	                                 (HelperSecretFunc) nm_setting_wireless_security_get_psk);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMAWsSae *self = NMA_WS_SAE (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_object (value, self->connection);
		break;
	case PROP_SECRETS_ONLY:
		g_value_set_boolean (value, self->secrets_only);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	NMAWsSae *self = NMA_WS_SAE (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		self->connection = g_value_dup_object (value);
		break;
	case PROP_SECRETS_ONLY:
		self->secrets_only = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nma_ws_sae_init (NMAWsSae *self)
{
	gtk_widget_init_template (GTK_WIDGET (self));
}

static void
nma_ws_interface_init (NMAWsInterface *iface)
{
	iface->validate = validate;
	iface->add_to_size_group = add_to_size_group;
	iface->fill_connection = fill_connection;
	iface->update_secrets = update_secrets;
	iface->adhoc_compatible = TRUE;
	iface->hotspot_compatible = TRUE;
}

static void
constructed (GObject *object)
{
	NMAWsSae *self = NMA_WS_SAE (object);
	NMSetting *setting = NULL;

	/* Create password-storage popup menu for password entry under entry's secondary icon */
	if (self->connection)
		setting = (NMSetting *) nm_connection_get_setting_wireless_security (self->connection);
	nma_utils_setup_password_storage (self->psk_entry, 0, setting, NM_SETTING_WIRELESS_SECURITY_PSK,
	                                  FALSE, self->secrets_only);

	/* Fill secrets, if any */
	if (self->connection)
		update_secrets (NMA_WS (self), self->connection);

	gtk_widget_grab_focus (self->psk_entry);

	G_OBJECT_CLASS (nma_ws_sae_parent_class)->constructed (object);
}

NMAWsSae *
nma_ws_sae_new (NMConnection *connection, gboolean secrets_only)
{
	return g_object_new (NMA_TYPE_WS_SAE,
	                     "connection", connection,
	                     "secrets-only", secrets_only,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMAWsSae *self = NMA_WS_SAE (object);

	g_clear_object (&self->connection);

	G_OBJECT_CLASS (nma_ws_sae_parent_class)->dispose (object);
}

static void
nma_ws_sae_class_init (NMAWsSaeClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GtkWidgetClass *widget_class = GTK_WIDGET_CLASS (klass);

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->constructed = constructed;
	object_class->dispose = dispose;

	g_object_class_override_property (object_class,
	                                  PROP_CONNECTION, "connection");

	g_object_class_override_property (object_class,
	                                  PROP_SECRETS_ONLY, "secrets-only");

        gtk_widget_class_set_template_from_resource (widget_class,
                                                     "/org/gnome/libnma/nma-ws-sae.ui");

	gtk_widget_class_bind_template_child (widget_class, NMAWsSae, psk_entry);
	gtk_widget_class_bind_template_child (widget_class, NMAWsSae, sae_label);

	gtk_widget_class_bind_template_callback (widget_class, nma_ws_changed_cb);
}
