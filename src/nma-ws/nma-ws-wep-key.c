// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2007 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <string.h>

#include "nma-ws.h"
#include "nma-ws-private.h"
#include "nma-ws-wep-key.h"
#include "nma-ws-helpers.h"
#include "nma-ui-utils.h"
#include "utils.h"

struct _NMAWsWepKey {
	GtkGrid parent;

	GtkWidget *auth_method_combo;
	GtkWidget *auth_method_label;
	GtkWidget *key_index_combo;
	GtkWidget *key_index_label;
	GtkWidget *wep_key_entry;
	GtkWidget *wep_key_label;

	NMConnection *connection;
	gboolean secrets_only;
	NMWepKeyType adhoc_create;
	NMWepKeyType key_type;

	char keys[4][65];
	guint8 cur_index;
};

struct _NMAWsWepKeyClass {
	GtkGridClass parent;
};

static void nma_ws_interface_init (NMAWsInterface *iface);

G_DEFINE_TYPE_WITH_CODE (NMAWsWepKey, nma_ws_wep_key, GTK_TYPE_GRID,
                         G_IMPLEMENT_INTERFACE (NMA_TYPE_WS, nma_ws_interface_init))

enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_SECRETS_ONLY,
	PROP_KEY_TYPE,
	PROP_ADHOC_CREATE,
	PROP_LAST
};

static void
key_index_combo_changed_cb (GtkWidget *combo, NMAWs *ws)
{
	NMAWsWepKey *self = NMA_WS_WEP_KEY (ws);
	GtkWidget *entry;
	const char *key;
	int key_index;

	/* Save WEP key for old key index */
	entry = GTK_WIDGET (self->wep_key_entry);
	key = gtk_editable_get_text (GTK_EDITABLE (entry));
	if (key)
		g_strlcpy (self->keys[self->cur_index], key, sizeof (self->keys[self->cur_index]));
	else
		memset (self->keys[self->cur_index], 0, sizeof (self->keys[self->cur_index]));

	key_index = gtk_combo_box_get_active (GTK_COMBO_BOX (combo));
	g_return_if_fail (key_index <= 3);
	g_return_if_fail (key_index >= 0);

	/* Populate entry with key from new index */
	gtk_editable_set_text (GTK_EDITABLE (entry), self->keys[key_index]);
	self->cur_index = key_index;

	nma_ws_changed_cb (combo, ws);
}

static gboolean
validate (NMAWs *ws, GError **error)
{
	NMAWsWepKey *self = NMA_WS_WEP_KEY (ws);
	NMSettingSecretFlags secret_flags;
	const char *key;
	int i;

	secret_flags = nma_utils_menu_to_secret_flags (self->wep_key_entry);
	key = gtk_editable_get_text (GTK_EDITABLE (self->wep_key_entry));

        if (   secret_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED
            || secret_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED) {
		/* All good. */
	} else if (!key) {
		widget_set_error (self->wep_key_entry);
		g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("missing wep-key"));
		return FALSE;
	} else if (self->key_type == NM_WEP_KEY_TYPE_KEY) {
		if ((strlen (key) == 10) || (strlen (key) == 26)) {
			for (i = 0; i < strlen (key); i++) {
				if (!g_ascii_isxdigit (key[i])) {
					widget_set_error (self->wep_key_entry);
					g_set_error (error, NMA_ERROR, NMA_ERROR_GENERIC, _("invalid wep-key: key with a length of %zu must contain only hex-digits"), strlen (key));
					return FALSE;
				}
			}
		} else if ((strlen (key) == 5) || (strlen (key) == 13)) {
			for (i = 0; i < strlen (key); i++) {
				if (!g_ascii_isprint (key[i])) {
					widget_set_error (self->wep_key_entry);
					g_set_error (error, NMA_ERROR, NMA_ERROR_GENERIC, _("invalid wep-key: key with a length of %zu must contain only ascii characters"), strlen (key));
					return FALSE;
				}
			}
		} else {
			widget_set_error (self->wep_key_entry);
			g_set_error (error, NMA_ERROR, NMA_ERROR_GENERIC, _("invalid wep-key: wrong key length %zu. A key must be either of length 5/13 (ascii) or 10/26 (hex)"), strlen (key));
			return FALSE;
		}
	} else if (self->key_type == NM_WEP_KEY_TYPE_PASSPHRASE) {
		if (!*key || (strlen (key) > 64)) {
			widget_set_error (self->wep_key_entry);
			if (!*key)
				g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("invalid wep-key: passphrase must be non-empty"));
			else
				g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("invalid wep-key: passphrase must be shorter than 64 characters"));
			return FALSE;
		}
	}
	widget_unset_error (self->wep_key_entry);

	return TRUE;
}

static void
add_to_size_group (NMAWs *ws, GtkSizeGroup *group)
{
	NMAWsWepKey *self = NMA_WS_WEP_KEY (ws);

	gtk_size_group_add_widget (group, self->auth_method_label);
	gtk_size_group_add_widget (group, self->wep_key_label);
	gtk_size_group_add_widget (group, self->key_index_label);
}

static void
fill_connection (NMAWs *ws, NMConnection *connection)
{
	NMAWsWepKey *self = NMA_WS_WEP_KEY (ws);
	NMSettingWirelessSecurity *s_wsec;
	NMSettingSecretFlags secret_flags;
	int auth_alg;
	const char *key;
	int i;

	auth_alg = gtk_combo_box_get_active (GTK_COMBO_BOX (self->auth_method_combo));
	key = gtk_editable_get_text (GTK_EDITABLE (self->wep_key_entry));
	g_strlcpy (self->keys[self->cur_index], key, sizeof (self->keys[self->cur_index]));

	/* Blow away the old security setting by adding a clear one */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, (NMSetting *) s_wsec);

	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none",
	              NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, self->cur_index,
	              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, (auth_alg == 1) ? "shared" : "open",
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, self->key_type,
	              NULL);

	for (i = 0; i < 4; i++) {
		if (strlen (self->keys[i]))
			nm_setting_wireless_security_set_wep_key (s_wsec, i, self->keys[i]);
	}

	/* Save WEP_KEY_FLAGS to the connection */
	secret_flags = nma_utils_menu_to_secret_flags (self->wep_key_entry);
	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS, secret_flags, NULL);

	/* Update secret flags and popup when editing the connection */
	if (!self->secrets_only) {
		nma_utils_update_password_storage (self->wep_key_entry, secret_flags,
		                                   NM_SETTING (s_wsec),
		                                   NM_SETTING_WIRELESS_SECURITY_WEP_KEY0);
	}
}

static gboolean
_ascii_isprint (char character)
{
       return g_ascii_isprint (character);
}

static void
wep_entry_filter_cb (GtkEditable *editable,
                     char *text,
                     int length,
                     int *position,
                     gpointer data)
{
	NMAWsWepKey *self = NMA_WS_WEP_KEY (data);

	if (self->key_type == NM_WEP_KEY_TYPE_KEY) {
		utils_filter_editable_on_insert_text (editable,
		                                      text, length, position, data,
		                                      _ascii_isprint,
		                                      wep_entry_filter_cb);
	}
}


static void
update_secrets (NMAWs *ws, NMConnection *connection)
{
	NMAWsWepKey *self = NMA_WS_WEP_KEY (ws);
	NMSettingWirelessSecurity *s_wsec;
	const char *tmp;
	int i;

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	for (i = 0; s_wsec && i < 4; i++) {
		tmp = nm_setting_wireless_security_get_wep_key (s_wsec, i);
		if (tmp)
			g_strlcpy (self->keys[i], tmp, sizeof (self->keys[i]));
	}

	if (strlen (self->keys[self->cur_index])) {
		gtk_editable_set_text (GTK_EDITABLE (self->wep_key_entry),
		                       self->keys[self->cur_index]);
	}
}


static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMAWsWepKey *self = NMA_WS_WEP_KEY (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_object (value, self->connection);
		break;
	case PROP_SECRETS_ONLY:
		g_value_set_boolean (value, self->secrets_only);
		break;
	case PROP_KEY_TYPE:
		g_value_set_uint (value, self->key_type);
		break;
	case PROP_ADHOC_CREATE:
		g_value_set_boolean (value, self->adhoc_create);
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
	NMAWsWepKey *self = NMA_WS_WEP_KEY (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		self->connection = g_value_dup_object (value);
		break;
	case PROP_SECRETS_ONLY:
		self->secrets_only = g_value_get_boolean (value);
		break;
	case PROP_KEY_TYPE:
		self->key_type = g_value_get_uint (value);
		break;
	case PROP_ADHOC_CREATE:
		self->adhoc_create = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nma_ws_wep_key_init (NMAWsWepKey *self)
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
	NMAWsWepKey *self = NMA_WS_WEP_KEY (object);
	NMSettingWirelessSecurity *s_wsec = NULL;
	NMSetting *setting = NULL;
	guint8 default_key_idx = 0;
	gboolean is_adhoc = self->adhoc_create;
	gboolean is_shared_key = FALSE;


	/* Create password-storage popup menu for password entry under entry's secondary icon */
	if (self->connection)
		setting = (NMSetting *) nm_connection_get_setting_wireless_security (self->connection);
	nma_utils_setup_password_storage (self->wep_key_entry, 0, setting,
	                                  NM_SETTING_WIRELESS_SECURITY_WEP_KEY0,
	                                  FALSE, self->secrets_only);

	if (self->connection) {
		NMSettingWireless *s_wireless;
		const char *mode, *auth_alg;

		s_wireless = nm_connection_get_setting_wireless (self->connection);
		mode = s_wireless ? nm_setting_wireless_get_mode (s_wireless) : NULL;
		if (mode && !strcmp (mode, "adhoc"))
			is_adhoc = TRUE;

		s_wsec = nm_connection_get_setting_wireless_security (self->connection);
		if (s_wsec) {
			auth_alg = nm_setting_wireless_security_get_auth_alg (s_wsec);
			if (auth_alg && !strcmp (auth_alg, "shared"))
				is_shared_key = TRUE;
		}
	}

	if (self->key_type == NM_WEP_KEY_TYPE_KEY)
		gtk_entry_set_max_length (GTK_ENTRY (self->wep_key_entry), 26);
	else if (self->key_type == NM_WEP_KEY_TYPE_PASSPHRASE)
		gtk_entry_set_max_length (GTK_ENTRY (self->wep_key_entry), 64);

	if (self->connection && s_wsec)
		default_key_idx = nm_setting_wireless_security_get_wep_tx_keyidx (s_wsec);

	gtk_combo_box_set_active (GTK_COMBO_BOX (self->key_index_combo), default_key_idx);
	self->cur_index = default_key_idx;

	/* Key index is useless with adhoc networks */
	if (is_adhoc || self->secrets_only) {
		gtk_widget_hide (self->key_index_combo);
	}

	/* Fill the key entry with the key for that index */
	if (self->connection)
		update_secrets (NMA_WS (self), self->connection);

	gtk_combo_box_set_active (GTK_COMBO_BOX (self->auth_method_combo),
	                          is_shared_key ? 1 : 0);

	/* Don't show auth method for adhoc (which always uses open-system) or
	 * when in "simple" mode.
	 */
	if (is_adhoc || self->secrets_only) {
		/* Ad-Hoc connections can't use Shared Key auth */
		if (is_adhoc)
			gtk_combo_box_set_active (GTK_COMBO_BOX (self->auth_method_combo), 0);
		gtk_widget_hide (self->auth_method_combo);
	}

	gtk_widget_grab_focus (self->wep_key_entry);

	G_OBJECT_CLASS (nma_ws_wep_key_parent_class)->constructed (object);
}

NMAWsWepKey *
nma_ws_wep_key_new (NMConnection *connection,
                    NMWepKeyType key_type,
                    gboolean adhoc_create,
                    gboolean secrets_only)
{
	return g_object_new (NMA_TYPE_WS_WEP_KEY,
	                     "connection", connection,
	                     "key-type", key_type,
	                     "adhoc-create", adhoc_create,
	                     "secrets-only", secrets_only,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMAWsWepKey *self = NMA_WS_WEP_KEY (object);

	g_clear_object (&self->connection);

	G_OBJECT_CLASS (nma_ws_wep_key_parent_class)->dispose (object);
}

static void
nma_ws_wep_key_class_init (NMAWsWepKeyClass *klass)
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

	g_object_class_install_property
		(object_class, PROP_KEY_TYPE,
		 g_param_spec_uint ("key-type", "", "",
		                    0, G_MAXUINT, 0,
		                      G_PARAM_READWRITE
		                    | G_PARAM_CONSTRUCT
		                    | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_ADHOC_CREATE,
		g_param_spec_boolean ("adhoc-create", "", "",
		                      FALSE,
		                        G_PARAM_READWRITE
		                      | G_PARAM_CONSTRUCT
		                      | G_PARAM_STATIC_STRINGS));

        gtk_widget_class_set_template_from_resource (widget_class,
                                                     "/org/gnome/libnma/nma-ws-wep-key.ui");

	gtk_widget_class_bind_template_child (widget_class, NMAWsWepKey, auth_method_combo);
	gtk_widget_class_bind_template_child (widget_class, NMAWsWepKey, auth_method_label);
	gtk_widget_class_bind_template_child (widget_class, NMAWsWepKey, key_index_combo);
	gtk_widget_class_bind_template_child (widget_class, NMAWsWepKey, key_index_label);
	gtk_widget_class_bind_template_child (widget_class, NMAWsWepKey, wep_key_entry);
	gtk_widget_class_bind_template_child (widget_class, NMAWsWepKey, wep_key_label);

	gtk_widget_class_bind_template_callback (widget_class, key_index_combo_changed_cb);
	gtk_widget_class_bind_template_callback (widget_class, nma_ws_changed_cb);
	gtk_widget_class_bind_template_callback (widget_class, wep_entry_filter_cb);
}
