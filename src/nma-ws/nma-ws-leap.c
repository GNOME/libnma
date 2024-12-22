// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright (C) 2007 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <string.h>

#include "nma-ws.h"
#include "nma-ws-private.h"
#include "nma-ws-leap.h"
#include "nma-ws-helpers.h"
#include "nma-ui-utils.h"
#include "utils.h"

struct _NMAWsLeap {
	GtkGrid parent;

	GtkWidget *leap_username_entry;
	GtkWidget *leap_password_entry;
	GtkWidget *leap_username_label;
	GtkWidget *leap_password_label;

	NMConnection *connection;
	gboolean secrets_only;
};

struct _NMAWsLeapClass {
	GtkGridClass parent;
};

static void nma_ws_interface_init (NMAWsInterface *iface);

G_DEFINE_TYPE_WITH_CODE (NMAWsLeap, nma_ws_leap, GTK_TYPE_GRID,
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
	NMAWsLeap *self = NMA_WS_LEAP (ws);
	NMSettingSecretFlags secret_flags;
	const char *text;
	gboolean ret = TRUE;

	text = gtk_editable_get_text (GTK_EDITABLE (self->leap_username_entry));
	if (!text || !*text) {
		widget_set_error (self->leap_username_entry);
		g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("missing leap-username"));
		ret = FALSE;
	} else {
		widget_unset_error (self->leap_username_entry);
	}

	secret_flags = nma_utils_menu_to_secret_flags (self->leap_password_entry);
	text = gtk_editable_get_text (GTK_EDITABLE (self->leap_password_entry));

	if (   secret_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED
	    || secret_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED
	    || (text && *text)) {
		widget_unset_error (self->leap_password_entry);
	} else {
		widget_set_error (self->leap_password_entry);
		if (ret) {
			g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("missing leap-password"));
			ret = FALSE;
		}
	}

	return ret;
}

static void
add_to_size_group (NMAWs *ws, GtkSizeGroup *group)
{
	NMAWsLeap *self = NMA_WS_LEAP (ws);

	gtk_size_group_add_widget (group, self->leap_username_label);
	gtk_size_group_add_widget (group, self->leap_password_label);
}

static void
fill_connection (NMAWs *ws, NMConnection *connection)
{
	NMAWsLeap *self = NMA_WS_LEAP (ws);
	NMSettingWirelessSecurity *s_wireless_sec;
	NMSettingSecretFlags secret_flags;
	const char *leap_password = NULL, *leap_username = NULL;

	/* Blow away the old security setting by adding a clear one */
	s_wireless_sec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, (NMSetting *) s_wireless_sec);

	leap_username = gtk_editable_get_text (GTK_EDITABLE (self->leap_username_entry));
	leap_password = gtk_editable_get_text (GTK_EDITABLE (self->leap_password_entry));

	g_object_set (s_wireless_sec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x",
	              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap",
	              NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, leap_username,
	              NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD, leap_password,
	              NULL);

	/* Save LEAP_PASSWORD_FLAGS to the connection */
	secret_flags = nma_utils_menu_to_secret_flags (self->leap_password_entry);
	nm_setting_set_secret_flags (NM_SETTING (s_wireless_sec), NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD,
	                             secret_flags, NULL);

	/* Update secret flags and popup when editing the connection */
	if (!self->secrets_only) {
		nma_utils_update_password_storage (self->leap_password_entry, secret_flags,
		                                   NM_SETTING (s_wireless_sec),
		                                   NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD);
	}
}

static void
update_secrets (NMAWs *ws, NMConnection *connection)
{
	NMAWsLeap *self = NMA_WS_LEAP (ws);

	nma_ws_helper_fill_secret_entry (connection,
	                                 GTK_EDITABLE (self->leap_password_entry),
	                                 NM_TYPE_SETTING_WIRELESS_SECURITY,
	                                 (HelperSecretFunc) nm_setting_wireless_security_get_leap_password);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMAWsLeap *self = NMA_WS_LEAP (object);

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
	NMAWsLeap *self = NMA_WS_LEAP (object);

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
nma_ws_leap_init (NMAWsLeap *self)
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
	iface->adhoc_compatible = FALSE;
	iface->hotspot_compatible = FALSE;
}

static void
constructed (GObject *object)
{
	NMAWsLeap *self = NMA_WS_LEAP (object);
	NMSettingWirelessSecurity *wsec = NULL;

	if (self->connection) {
		wsec = nm_connection_get_setting_wireless_security (self->connection);
		if (wsec) {
			const char *auth_alg;

			/* Ignore if wireless security doesn't specify LEAP */
			auth_alg = nm_setting_wireless_security_get_auth_alg (wsec);
			if (!auth_alg || strcmp (auth_alg, "leap"))
				wsec = NULL;
		}
	}

	/* Create password-storage popup menu for password entry under entry's secondary icon */
	nma_utils_setup_password_storage (self->leap_password_entry, 0, (NMSetting *) wsec,
	                                  NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD,
	                                  FALSE, self->secrets_only);

	if (wsec) {
		update_secrets (NMA_WS (self), self->connection);
		gtk_editable_set_text (GTK_EDITABLE (self->leap_username_entry),
		                       nm_setting_wireless_security_get_leap_username (wsec));
	}

	if (self->secrets_only) {
		gtk_widget_hide (self->leap_username_entry);
	}

	gtk_widget_grab_focus (self->leap_password_entry);

	G_OBJECT_CLASS (nma_ws_leap_parent_class)->constructed (object);
}

NMAWsLeap *
nma_ws_leap_new (NMConnection *connection, gboolean secrets_only)
{
	return g_object_new (NMA_TYPE_WS_LEAP,
	                     "connection", connection,
	                     "secrets-only", secrets_only,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMAWsLeap *self = NMA_WS_LEAP (object);

	g_clear_object (&self->connection);

	G_OBJECT_CLASS (nma_ws_leap_parent_class)->dispose (object);
}

static void
nma_ws_leap_class_init (NMAWsLeapClass *klass)
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
                                                     "/org/gnome/libnma/nma-ws-leap.ui");

	gtk_widget_class_bind_template_child (widget_class, NMAWsLeap, leap_username_entry);
	gtk_widget_class_bind_template_child (widget_class, NMAWsLeap, leap_password_entry);
	gtk_widget_class_bind_template_child (widget_class, NMAWsLeap, leap_username_label);
	gtk_widget_class_bind_template_child (widget_class, NMAWsLeap, leap_password_label);

	gtk_widget_class_bind_template_callback (widget_class, nma_ws_changed_cb);
}
