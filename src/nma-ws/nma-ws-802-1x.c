// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2007 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <string.h>

#include "nma-ws.h"
#include "nma-ws-private.h"
#include "nma-ws-802-1x.h"
#include "nma-ws-802-1x-private.h"
#include "nma-ws-helpers.h"
#include "nma-ui-utils.h"

#include "nma-eap-tls.h"
#include "nma-eap-leap.h"
#include "nma-eap-fast.h"
#include "nma-eap-ttls.h"
#include "nma-eap-peap.h"
#include "nma-eap-simple.h"
#include "nma-eap.h"

#include "utils.h"

#define AUTH_NAME_COLUMN   0
#define AUTH_METHOD_COLUMN 1

static void nma_ws_interface_init (NMAWsInterface *iface);

G_DEFINE_TYPE_WITH_CODE (NMAWs8021x, nma_ws_802_1x, GTK_TYPE_GRID,
                         G_IMPLEMENT_INTERFACE (NMA_TYPE_WS, nma_ws_interface_init))

enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_SECRETS_ONLY,
	PROP_IS_EDITOR,
	PROP_SECRETS_HINTS,
	PROP_LAST
};

void
nma_ws_802_1x_set_userpass (NMAWs8021x *self,
                            const char *user,
                            const char *password,
                            gboolean always_ask,
                            gboolean show_password)
{
	g_free (self->username);
	self->username = g_strdup (user);

	if (self->password) {
		memset (self->password, 0, strlen (self->password));
		g_free (self->password);
	}
	self->password = g_strdup (password);

	if (always_ask != (gboolean) -1)
		self->always_ask = always_ask;
	self->show_password = show_password;
}

static void
init_userpass (NMAWs8021x *self, NMConnection *connection)
{
	const char *user = NULL, *password = NULL;
	gboolean always_ask = FALSE, show_password = FALSE;
	NMSetting8021x  *setting;
	NMSettingSecretFlags flags;

	if (!connection)
		goto set;

	setting = nm_connection_get_setting_802_1x (connection);
	if (!setting)
		goto set;

	user = nm_setting_802_1x_get_identity (setting);
	password = nm_setting_802_1x_get_password (setting);

	if (nm_setting_get_secret_flags (NM_SETTING (setting), NM_SETTING_802_1X_PASSWORD, &flags, NULL))
		always_ask = !!(flags & NM_SETTING_SECRET_FLAG_NOT_SAVED);

set:
	nma_ws_802_1x_set_userpass (self, user, password, always_ask, show_password);
}

static gboolean
validate (NMAWs *ws, GError **error)
{
	NMAWs8021x *self = NMA_WS_802_1X (ws);
	GtkTreeModel *model;
	GtkTreeIter iter;
	NMAEap *eap = NULL;
	gboolean valid = FALSE;

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (self->eap_auth_combo));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (self->eap_auth_combo), &iter);
	gtk_tree_model_get (model, &iter, AUTH_METHOD_COLUMN, &eap, -1);
	g_return_val_if_fail (eap, FALSE);
	valid = nma_eap_validate (eap, error);
	nma_eap_unref (eap);
	return valid;
}

static void
auth_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	NMAWs8021x *self = NMA_WS_802_1X (user_data);

	NMAEap *eap = NULL;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkWidget *eap_default_widget = NULL;

	/* Remove any previous wireless security widgets */
	if (self->eap_widget)
		gtk_box_remove (self->eap_vbox, self->eap_widget);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter);
	gtk_tree_model_get (model, &iter, AUTH_METHOD_COLUMN, &eap, -1);
	g_return_if_fail (eap);

	self->eap_widget = nma_eap_get_widget (eap);
	g_return_if_fail (self->eap_widget);
	gtk_widget_unparent (self->eap_widget);

	gtk_box_append (self->eap_vbox, self->eap_widget);

	/* Refocus the EAP method's default widget */
	if (eap->default_field) {
		eap_default_widget = GTK_WIDGET (gtk_builder_get_object (eap->builder, eap->default_field));
		if (eap_default_widget)
			gtk_widget_grab_focus (eap_default_widget);
	}

	nma_eap_unref (eap);

	nma_ws_changed_cb (combo, NMA_WS (self));
}

static void
add_to_size_group (NMAWs *ws, GtkSizeGroup *group)
{
	NMAWs8021x *self = NMA_WS_802_1X (ws);
	NMAEap *eap = NULL;
	GtkTreeModel *model;
	GtkTreeIter iter;

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (self->eap_auth_combo));

	/* Let each EAP method try to update its secrets */
	if (gtk_tree_model_get_iter_first (model, &iter)) {
		do {
			gtk_tree_model_get (model, &iter, AUTH_METHOD_COLUMN, &eap, -1);
			if (eap) {
				nma_eap_add_to_size_group (eap, group);
				nma_eap_unref (eap);
			}
		} while (gtk_tree_model_iter_next (model, &iter));
	}

	gtk_size_group_add_widget (group, self->eap_auth_label);
}

void
nma_ws_802_1x_fill_connection (NMAWs *ws, NMConnection *connection)
{
	NMAWs8021x *self = NMA_WS_802_1X (ws);
	NMSettingWirelessSecurity *s_wireless_sec;
	NMSetting8021x *s_8021x;
	NMAEap *eap = NULL;
	GtkTreeModel *model;
	GtkTreeIter iter;

	/* Get the NMAEap object */
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (self->eap_auth_combo));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (self->eap_auth_combo), &iter);
	gtk_tree_model_get (model, &iter, AUTH_METHOD_COLUMN, &eap, -1);
	g_return_if_fail (eap);

	/* Blow away the old wireless security setting by adding a clear one */
	s_wireless_sec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, (NMSetting *) s_wireless_sec);

	/* Blow away the old 802.1x setting by adding a clear one */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	nm_connection_add_setting (connection, (NMSetting *) s_8021x);

	nma_eap_fill_connection (eap, connection);
	nma_eap_unref (eap);
}

static void
update_secrets (NMAWs *ws, NMConnection *connection)
{
	NMAWs8021x *self = NMA_WS_802_1X (ws);
	NMAEap *eap = NULL;
	GtkTreeModel *model;
	GtkTreeIter iter;

	g_return_if_fail (connection != NULL);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (self->eap_auth_combo));

	/* Let each EAP method try to update its secrets */
	if (gtk_tree_model_get_iter_first (model, &iter)) {
		do {
			gtk_tree_model_get (model, &iter, AUTH_METHOD_COLUMN, &eap, -1);
			if (eap) {
				nma_eap_update_secrets (eap, connection);
				nma_eap_unref (eap);
			}
		} while (gtk_tree_model_iter_next (model, &iter));
	}
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMAWs8021x *self = NMA_WS_802_1X (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_object (value, self->connection);
		break;
	case PROP_SECRETS_ONLY:
		g_value_set_boolean (value, self->secrets_only);
		break;
	case PROP_IS_EDITOR:
		g_value_set_boolean (value, self->is_editor);
		break;
	case PROP_SECRETS_HINTS:
		g_value_set_boxed (value, self->secrets_hints);
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
	NMAWs8021x *self = NMA_WS_802_1X (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		self->connection = g_value_dup_object (value);
		break;
	case PROP_SECRETS_ONLY:
		self->secrets_only = g_value_get_boolean (value);
		break;
	case PROP_IS_EDITOR:
		self->is_editor = g_value_get_boolean (value);
		break;
	case PROP_SECRETS_HINTS:
		self->secrets_hints = g_value_dup_boxed (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nma_ws_802_1x_init (NMAWs8021x *self)
{
	gtk_widget_init_template (GTK_WIDGET (self));
}

static void
nma_ws_interface_init (NMAWsInterface *iface)
{
	iface->validate = validate;
	iface->add_to_size_group = add_to_size_group;
	iface->fill_connection = nma_ws_802_1x_fill_connection;
	iface->update_secrets = update_secrets;
	iface->adhoc_compatible = FALSE;
	iface->hotspot_compatible = FALSE;
}

static void
constructed (GObject *object)
{
	NMAWs8021x *self = NMA_WS_802_1X (object);
	GtkListStore *auth_model;
	GtkTreeIter iter;
	NMAEapSimple *em_md5;
	NMAEapTls *em_tls;
	NMAEapLeap *em_leap;
	NMAEapSimple *em_pwd;
	NMAEapFast *em_fast;
	NMAEapTtls *em_ttls;
	NMAEapPeap *em_peap;
	const char *default_method = NULL, *ctype = NULL;
	int active = -1, item = 0;
	gboolean wired = FALSE;
	NMAEapSimpleFlags simple_flags = NMA_EAP_SIMPLE_FLAG_NONE;

	/* Grab the default EAP method out of the security object */
	if (self->connection) {
		NMSettingConnection *s_con;
		NMSetting8021x *s_8021x;

		s_con = nm_connection_get_setting_connection (self->connection);
		if (s_con)
			ctype = nm_setting_connection_get_connection_type (s_con);
		if (   (g_strcmp0 (ctype, NM_SETTING_WIRED_SETTING_NAME) == 0)
		    || nm_connection_get_setting_wired (self->connection))
			wired = TRUE;

		s_8021x = nm_connection_get_setting_802_1x (self->connection);
		if (s_8021x && nm_setting_802_1x_get_num_eap_methods (s_8021x))
			default_method = nm_setting_802_1x_get_eap_method (s_8021x, 0);
	}

	/* initialize NMAWs userpass from connection (clear if no connection) */
	init_userpass (self, self->connection);

	auth_model = gtk_list_store_new (2, G_TYPE_STRING, nma_eap_get_type ());

	if (self->is_editor)
		simple_flags |= NMA_EAP_SIMPLE_FLAG_IS_EDITOR;
	if (self->secrets_only)
		simple_flags |= NMA_EAP_SIMPLE_FLAG_SECRETS_ONLY;

	if (wired) {
		em_md5 = nma_eap_simple_new (self, self->connection, NMA_EAP_SIMPLE_TYPE_MD5, simple_flags, NULL);
		gtk_list_store_append (auth_model, &iter);
		gtk_list_store_set (auth_model, &iter,
		                    AUTH_NAME_COLUMN, _("MD5"),
		                    AUTH_METHOD_COLUMN, em_md5,
		                    -1);
		nma_eap_unref (NMA_EAP (em_md5));
		if (default_method && (active < 0) && !strcmp (default_method, "md5"))
			active = item;
		item++;
	}

	em_tls = nma_eap_tls_new (self, self->connection, FALSE, self->secrets_only);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    AUTH_NAME_COLUMN, _("TLS"),
	                    AUTH_METHOD_COLUMN, em_tls,
	                    -1);
	nma_eap_unref (NMA_EAP (em_tls));
	if (default_method && (active < 0) && !strcmp (default_method, "tls"))
		active = item;
	item++;

	if (!wired) {
		em_leap = nma_eap_leap_new (self, self->connection, self->secrets_only);
		gtk_list_store_append (auth_model, &iter);
		gtk_list_store_set (auth_model, &iter,
		                    AUTH_NAME_COLUMN, _("LEAP"),
		                    AUTH_METHOD_COLUMN, em_leap,
		                    -1);
		nma_eap_unref (NMA_EAP (em_leap));
		if (default_method && (active < 0) && !strcmp (default_method, "leap"))
			active = item;
		item++;
	}

	em_pwd = nma_eap_simple_new (self, self->connection, NMA_EAP_SIMPLE_TYPE_PWD, simple_flags, NULL);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    AUTH_NAME_COLUMN, _("PWD"),
	                    AUTH_METHOD_COLUMN, em_pwd,
	                    -1);
	nma_eap_unref (NMA_EAP (em_pwd));
	if (default_method && (active < 0) && !strcmp (default_method, "pwd"))
		active = item;
	item++;

	em_fast = nma_eap_fast_new (self, self->connection, self->is_editor, self->secrets_only);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    AUTH_NAME_COLUMN, _("FAST"),
	                    AUTH_METHOD_COLUMN, em_fast,
	                    -1);
	nma_eap_unref (NMA_EAP (em_fast));
	if (default_method && (active < 0) && !strcmp (default_method, "fast"))
		active = item;
	item++;

	em_ttls = nma_eap_ttls_new (self, self->connection, self->is_editor, self->secrets_only);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    AUTH_NAME_COLUMN, _("Tunneled TLS"),
	                    AUTH_METHOD_COLUMN, em_ttls,
	                    -1);
	nma_eap_unref (NMA_EAP (em_ttls));
	if (default_method && (active < 0) && !strcmp (default_method, "ttls"))
		active = item;
	item++;

	em_peap = nma_eap_peap_new (self, self->connection, self->is_editor, self->secrets_only);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    AUTH_NAME_COLUMN, _("Protected EAP (PEAP)"),
	                    AUTH_METHOD_COLUMN, em_peap,
	                    -1);
	nma_eap_unref (NMA_EAP (em_peap));
	if (default_method && (active < 0) && !strcmp (default_method, "peap"))
		active = item;
	item++;

	if (self->secrets_hints && self->secrets_hints[0]) {
		NMAEapSimple *em_hints;

		em_hints = nma_eap_simple_new (self, self->connection, NMA_EAP_SIMPLE_TYPE_UNKNOWN,
		                               simple_flags, (const char **)self->secrets_hints);
		gtk_list_store_append (auth_model, &iter);
		gtk_list_store_set (auth_model, &iter,
		                    AUTH_NAME_COLUMN, _("Unknown"),
		                    AUTH_METHOD_COLUMN, em_hints,
		                    -1);
		nma_eap_unref (NMA_EAP (em_hints));
		active = item;
		item++;
	} else if (default_method && !strcmp (default_method, "external")) {
		NMAEapSimple *em_extern;
		const char *empty_hints[] = { NULL };

		em_extern = nma_eap_simple_new (self, self->connection, NMA_EAP_SIMPLE_TYPE_UNKNOWN,
		                                simple_flags, empty_hints);
		gtk_list_store_append (auth_model, &iter);
		gtk_list_store_set (auth_model, &iter,
		                    AUTH_NAME_COLUMN, _("Externally configured"),
		                    AUTH_METHOD_COLUMN, em_extern,
		                    -1);
		nma_eap_unref (NMA_EAP (em_extern));
			active = item;
		item++;
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX (self->eap_auth_combo), GTK_TREE_MODEL (auth_model));
	g_object_unref (G_OBJECT (auth_model));
	gtk_combo_box_set_active (GTK_COMBO_BOX (self->eap_auth_combo), active < 0 ? 0 : (guint32) active);

	if (self->secrets_only) {
		gtk_widget_hide (self->eap_auth_combo);
	}

	G_OBJECT_CLASS (nma_ws_802_1x_parent_class)->constructed (object);
}

NMAWs8021x *
nma_ws_802_1x_new (NMConnection *connection,
                   gboolean is_editor,
                   gboolean secrets_only)
{
	return g_object_new (NMA_TYPE_WS_802_1X,
	                     "connection", connection,
	                     "is-editor", is_editor,
	                     "secrets-only", secrets_only,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMAWs8021x *self = NMA_WS_802_1X (object);

	g_clear_object (&self->connection);
	g_clear_pointer (&self->secrets_hints, g_strfreev);
	g_clear_pointer (&self->username, g_free);
	g_clear_pointer (&self->password, g_free);

	G_OBJECT_CLASS (nma_ws_802_1x_parent_class)->dispose (object);
}

static void
nma_ws_802_1x_class_init (NMAWs8021xClass *klass)
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
		(object_class, PROP_IS_EDITOR,
		 g_param_spec_boolean ("is-editor", "", "",
		                       FALSE,
		                         G_PARAM_READWRITE
		                       | G_PARAM_CONSTRUCT
		                       | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_SECRETS_HINTS,
		 g_param_spec_boxed ("secrets-hints", "", "",
		                     G_TYPE_STRV,
		                       G_PARAM_READWRITE
		                     | G_PARAM_CONSTRUCT
		                     | G_PARAM_STATIC_STRINGS));

	gtk_widget_class_set_template_from_resource (widget_class,
	                                             "/org/gnome/libnma/nma-ws-802-1x.ui");

	gtk_widget_class_bind_template_child (widget_class, NMAWs8021x, eap_auth_combo);
	gtk_widget_class_bind_template_child (widget_class, NMAWs8021x, eap_auth_label);
	gtk_widget_class_bind_template_child (widget_class, NMAWs8021x, eap_vbox);

	gtk_widget_class_bind_template_callback (widget_class, auth_combo_changed_cb);
}
