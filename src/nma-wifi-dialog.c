// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager Applet -- allow user control over networking
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright (C) 2007 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <string.h>
#include <NetworkManager.h>

#include "nma-wifi-dialog.h"
#include "nma-ws.h"
#include "nma-eap.h"

G_DEFINE_TYPE (NMAWifiDialog, nma_wifi_dialog, GTK_TYPE_DIALOG)

#define NMA_WIFI_DIALOG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                        NMA_TYPE_WIFI_DIALOG, \
                                        NMAWifiDialogPrivate))

typedef struct {
	NMAWifiDialog *self;
	NMConnection *connection;
	gboolean canceled;
} GetSecretsInfo;

typedef struct {
	NMClient *client;

	GtkBuilder *builder;

	NMConnection *specific_connection;
	NMConnection *connection;
	NMDevice *device;
	NMAccessPoint *ap;
	guint operation;

	GtkTreeModel *device_model;
	GtkTreeModel *connection_model;
	GtkSizeGroup *group;
	GtkWidget *sec_combo;
	GtkWidget *ok_response_button;

	gboolean network_name_focus;

	gboolean secrets_only;

	guint revalidate_id;

	GetSecretsInfo *secrets_info;

	NMAWs *ws;
} NMAWifiDialogPrivate;

enum {
	OP_NONE = 0,
	OP_CREATE_ADHOC,
	OP_CONNECT_HIDDEN,
};

#define D_NAME_COLUMN		0
#define D_DEV_COLUMN		1

#define S_NAME_COLUMN		0
#define S_SEC_COLUMN		1

#define C_NAME_COLUMN		0
#define C_CON_COLUMN		1
#define C_SEP_COLUMN		2
#define C_NEW_COLUMN		3

static gboolean security_combo_init (NMAWifiDialog *self, gboolean secrets_only,
                                     const char *secrets_setting_name,
                                     const char *const*secrets_hints);
static void ssid_entry_changed (GtkWidget *entry, gpointer user_data);

void
nma_wifi_dialog_set_nag_ignored (NMAWifiDialog *self, gboolean ignored)
{
}

gboolean
nma_wifi_dialog_get_nag_ignored (NMAWifiDialog *self)
{
	return TRUE;
}

static void
size_group_clear (GtkSizeGroup *group)
{
	GSList *iter;

	g_return_if_fail (group != NULL);

	iter = gtk_size_group_get_widgets (group);
	while (iter) {
		gtk_size_group_remove_widget (group, GTK_WIDGET (iter->data));
		iter = gtk_size_group_get_widgets (group);
	}
}

static void
_set_ok_sensitive (NMAWifiDialog *self, gboolean is_sensitive, const char *error_tooltip)
{
	NMAWifiDialogPrivate *priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);
	gtk_dialog_set_response_sensitive (GTK_DIALOG (self), GTK_RESPONSE_OK, is_sensitive);

	if (priv->ok_response_button) {
		gtk_widget_set_tooltip_text (priv->ok_response_button,
		                             is_sensitive ? _("Click to connect") : error_tooltip);
	}
}

static void
size_group_add_permanent (GtkSizeGroup *group,
                          GtkBuilder *builder)
{
	GtkWidget *widget;

	g_return_if_fail (group != NULL);
	g_return_if_fail (builder != NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "network_name_label"));
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "security_combo_label"));
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "device_label"));
	gtk_size_group_add_widget (group, widget);
}

static GBytes *
validate_dialog_ssid (NMAWifiDialog *self)
{
	NMAWifiDialogPrivate *priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *ssid;
	GBytes *ssid_bytes;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "network_name_entry"));

	ssid = gtk_editable_get_text (GTK_EDITABLE (widget));

	if (!ssid || strlen (ssid) == 0 || strlen (ssid) > 32)
		return NULL;

	ssid_bytes = g_bytes_new (ssid, strlen (ssid));
	return ssid_bytes;
}

static void
stuff_changed_cb (NMAWs *ws, gpointer user_data)
{
	NMAWifiDialog *self = NMA_WIFI_DIALOG (user_data);
	NMAWifiDialogPrivate *priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);
	GBytes *ssid = NULL;
	gboolean free_ssid = TRUE;
	gboolean valid = FALSE;
	GtkTreeModel *model;
	GtkTreeIter iter;
	NMAWs *sel_ws = NULL;
	gs_free_error GError *error = NULL;

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (priv->sec_combo));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (priv->sec_combo), &iter))
		gtk_tree_model_get (model, &iter, S_SEC_COLUMN, &sel_ws, -1);

	if (sel_ws)
		g_object_unref (sel_ws);

	if (sel_ws != ws)
		return;

	if (priv->connection) {
		NMSettingWireless *s_wireless;
		s_wireless = nm_connection_get_setting_wireless (priv->connection);
		g_assert (s_wireless);
		ssid = nm_setting_wireless_get_ssid (s_wireless);
		free_ssid = FALSE;
	} else {
		ssid = validate_dialog_ssid (self);
	}

	if (ssid) {
		valid = nma_ws_validate (ws, &error);
		if (free_ssid)
			g_bytes_unref (ssid);
	}

	/* But if there's an in-progress secrets call (which might require authorization)
	 * then we don't want to enable the OK button because we don't have all the
	 * connection details yet.
	 */
	if (priv->secrets_info)
		valid = FALSE;

	_set_ok_sensitive (self, valid, error ? error->message : NULL);
}

static void
security_combo_changed (GtkWidget *combo,
                        gpointer user_data)
{
	NMAWifiDialog *self = NMA_WIFI_DIALOG (user_data);
	NMAWifiDialogPrivate *priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);
	GtkWidget *vbox; // *def_widget;
	GtkTreeIter iter;
	GtkTreeModel *model;

	vbox = GTK_WIDGET (gtk_builder_get_object (priv->builder, "security_vbox"));
	g_assert (vbox);

	size_group_clear (priv->group);

	/* Remove the previous wireless security widget */
	if (priv->ws)
		gtk_box_remove (GTK_BOX (vbox), GTK_WIDGET (priv->ws));

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
	if (!gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter)) {
		g_warning ("%s: no active security combo box item.", __func__);
		return;
	}

	gtk_tree_model_get (model, &iter, S_SEC_COLUMN, &priv->ws, -1);
	if (!priv->ws) {
		/* Revalidate dialog if the user picked "None" so the OK button
		 * gets enabled if there's already a valid SSID.
		 */
		ssid_entry_changed (NULL, self);
		return;
	}

	gtk_widget_unparent (GTK_WIDGET (priv->ws));

	size_group_add_permanent (priv->group, priv->builder);
	nma_ws_add_to_size_group (priv->ws, priv->group);

	gtk_box_append (GTK_BOX (vbox), GTK_WIDGET (priv->ws));

	/* Re-validate */
	stuff_changed_cb (priv->ws, self);

#if 0
	/* Set focus to the security method's default widget, but only if the
	 * network name entry should not be focused.
	 */
	if (!priv->network_name_focus && sec->default_field) {
		def_widget = GTK_WIDGET (gtk_builder_get_object (sec->builder, sec->default_field));
		if (def_widget)
			gtk_widget_grab_focus (def_widget);
	}
#endif

	g_object_unref (priv->ws);
}

static void
security_combo_changed_manually (GtkWidget *combo,
                                 gpointer user_data)
{
	NMAWifiDialog *self = NMA_WIFI_DIALOG (user_data);
	NMAWifiDialogPrivate *priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);

	/* Flag that the combo was changed manually to allow focus to move
	 * to the security method's default widget instead of the network name.
	 */
	priv->network_name_focus = FALSE;
	security_combo_changed (combo, user_data);
}

static void
ssid_entry_changed (GtkWidget *entry, gpointer user_data)
{
	NMAWifiDialog *self = NMA_WIFI_DIALOG (user_data);
	NMAWifiDialogPrivate *priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);
	GtkTreeIter iter;
	NMAWs *ws = NULL;
	GtkTreeModel *model;
	gboolean valid = FALSE;
	GBytes *ssid;
	gs_free_error GError *error = NULL;

	/* If the network name entry was touched at all, allow focus to go to
	 * the default widget of the security method now.
	 */
	priv->network_name_focus = FALSE;

	ssid = validate_dialog_ssid (self);
	if (!ssid)
		goto out;

	g_bytes_unref (ssid);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (priv->sec_combo));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (priv->sec_combo), &iter))
		gtk_tree_model_get (model, &iter, S_SEC_COLUMN, &ws, -1);

	if (ws) {
		valid = nma_ws_validate (ws, &error);
		g_object_unref (ws);
	} else {
		valid = TRUE;
	}

out:
	/* But if there's an in-progress secrets call (which might require authorization)
	 * then we don't want to enable the OK button because we don't have all the
	 * connection details yet.
	 */
	if (priv->secrets_info)
		valid = FALSE;

	_set_ok_sensitive (self, valid, error ? error->message : NULL);
}

static void
connection_combo_changed (GtkWidget *combo,
                          gpointer user_data)
{
	NMAWifiDialog *self = NMA_WIFI_DIALOG (user_data);
	NMAWifiDialogPrivate *priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);
	GtkTreeIter iter;
	GtkTreeModel *model;
	gboolean is_new = FALSE;
	NMSettingWireless *s_wireless;
	char *utf8_ssid;
	GtkWidget *widget;

	if (!gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter)) {
		g_warning ("%s: no active connection combo box item.", __func__);
		return;
	}

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));

	if (priv->connection)
		g_object_unref (priv->connection);

	gtk_tree_model_get (model, &iter,
	                    C_CON_COLUMN, &priv->connection,
	                    C_NEW_COLUMN, &is_new, -1);

	if (priv->connection)
		nma_eap_ca_cert_ignore_load (priv->connection);

	if (!security_combo_init (self, priv->secrets_only, NULL, NULL)) {
		g_warning ("Couldn't change Wi-Fi security combo box.");
		return;
	}
	security_combo_changed (priv->sec_combo, self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "network_name_entry"));
	if (priv->connection) {
		GBytes *ssid;

		s_wireless = nm_connection_get_setting_wireless (priv->connection);
		ssid = nm_setting_wireless_get_ssid (s_wireless);
		utf8_ssid = nm_utils_ssid_to_utf8 (g_bytes_get_data (ssid, NULL), g_bytes_get_size (ssid));
		gtk_editable_set_text (GTK_EDITABLE (widget), utf8_ssid);
		g_free (utf8_ssid);
	} else {
		gtk_editable_set_text (GTK_EDITABLE (widget), "");
	}

	gtk_widget_set_sensitive (GTK_WIDGET (gtk_builder_get_object (priv->builder, "network_name_entry")), is_new);
	gtk_widget_set_sensitive (GTK_WIDGET (gtk_builder_get_object (priv->builder, "security_combo")), is_new);
	gtk_widget_set_sensitive (GTK_WIDGET (gtk_builder_get_object (priv->builder, "security_vbox")), is_new);
}

static gboolean
connection_combo_separator_cb (GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	gboolean is_separator = FALSE;

	gtk_tree_model_get (model, iter, C_SEP_COLUMN, &is_separator, -1);
	return is_separator;
}

static gint
alphabetize_connections (NMConnection *a, NMConnection *b)
{
	NMSettingConnection *asc, *bsc;

	asc = nm_connection_get_setting_connection (a);
	bsc = nm_connection_get_setting_connection (b);

	return strcmp (nm_setting_connection_get_id (asc),
		       nm_setting_connection_get_id (bsc));
}

static gboolean
connection_combo_init (NMAWifiDialog *self)
{
	NMAWifiDialogPrivate *priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);
	GtkListStore *store;
	int num_added = 0;
	GtkTreeIter tree_iter;
	GtkWidget *widget;
	NMSettingConnection *s_con;
	GtkCellRenderer *renderer;
	const char *id;

	g_clear_object (&priv->connection_model);
	g_clear_object (&priv->connection);

	/* New model */
	store = gtk_list_store_new (4, G_TYPE_STRING, G_TYPE_OBJECT, G_TYPE_BOOLEAN, G_TYPE_BOOLEAN);
	priv->connection_model = GTK_TREE_MODEL (store);

	if (priv->specific_connection) {
		s_con = nm_connection_get_setting_connection (priv->specific_connection);
		g_assert (s_con);
		id = nm_setting_connection_get_id (s_con);
		if (id == NULL) {
			/* New connections which will be completed by NM won't have an ID
			 * yet, but that doesn't matter because we don't show the connection
			 * combo anyway when there's a predefined connection.
			 */
			id = "blahblah";
		}

		gtk_list_store_append (store, &tree_iter);
		gtk_list_store_set (store, &tree_iter,
		                    C_NAME_COLUMN, id,
		                    C_CON_COLUMN, priv->specific_connection, -1);
	} else {
		GSList *to_add = NULL, *iter;
		const GPtrArray *connections;
		int i;

		gtk_list_store_append (store, &tree_iter);
		gtk_list_store_set (store, &tree_iter,
		                    C_NAME_COLUMN, _("New…"),
		                    C_NEW_COLUMN, TRUE, -1);

		gtk_list_store_append (store, &tree_iter);
		gtk_list_store_set (store, &tree_iter, C_SEP_COLUMN, TRUE, -1);

		connections = nm_client_get_connections (priv->client);
		for (i = 0; i < connections->len; i++) {
			NMConnection *candidate = NM_CONNECTION (connections->pdata[i]);
			NMSettingWireless *s_wireless;
			const char *connection_type;
			const char *mode;
			const char *setting_mac, *hw_addr;

			s_con = nm_connection_get_setting_connection (candidate);
			connection_type = s_con ? nm_setting_connection_get_connection_type (s_con) : NULL;
			if (!connection_type)
				continue;

			if (strcmp (connection_type, NM_SETTING_WIRELESS_SETTING_NAME))
				continue;

			s_wireless = nm_connection_get_setting_wireless (candidate);
			if (!s_wireless)
				continue;

			/* If creating a new Ad-Hoc network, only show shared network connections */
			if (priv->operation == OP_CREATE_ADHOC) {
				NMSettingIPConfig *s_ip4;
				const char *method = NULL;

				s_ip4 = nm_connection_get_setting_ip4_config (candidate);
				if (s_ip4)
					method = nm_setting_ip_config_get_method (s_ip4);

				if (!s_ip4 || strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
					continue;

				/* Ignore non-Ad-Hoc connections too */
				mode = nm_setting_wireless_get_mode (s_wireless);
				if (!mode || (strcmp (mode, "adhoc") && strcmp (mode, "ap")))
					continue;
			}

			/* Ignore connections that don't apply to the selected device */
			setting_mac = nm_setting_wireless_get_mac_address (s_wireless);
			hw_addr = nm_device_wifi_get_hw_address (NM_DEVICE_WIFI (priv->device));
			if (   setting_mac
			    && hw_addr 
			    && !nm_utils_hwaddr_matches (setting_mac, -1, hw_addr, -1))
				continue;

			to_add = g_slist_append (to_add, candidate);
		}

		/* Alphabetize the list then add the connections */
		to_add = g_slist_sort (to_add, (GCompareFunc) alphabetize_connections);
		for (iter = to_add; iter; iter = g_slist_next (iter)) {
			NMConnection *candidate = NM_CONNECTION (iter->data);

			s_con = nm_connection_get_setting_connection (candidate);
			gtk_list_store_append (store, &tree_iter);
			gtk_list_store_set (store, &tree_iter,
			                    C_NAME_COLUMN, nm_setting_connection_get_id (s_con),
			                    C_CON_COLUMN, candidate, -1);
			num_added++;
		}
		g_slist_free (to_add);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "connection_combo"));

	gtk_cell_layout_clear (GTK_CELL_LAYOUT (widget));
	renderer = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (widget), renderer, TRUE);
	gtk_cell_layout_add_attribute (GTK_CELL_LAYOUT (widget), renderer,
	                               "text", C_NAME_COLUMN);
#if !GTK_CHECK_VERSION(4,0,0)
	gtk_combo_box_set_wrap_width (GTK_COMBO_BOX (widget), 1);
#endif

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), priv->connection_model);

	gtk_combo_box_set_row_separator_func (GTK_COMBO_BOX (widget),
	                                      connection_combo_separator_cb,
	                                      NULL,
	                                      NULL);

	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);

	g_signal_handlers_disconnect_by_func (widget, connection_combo_changed, self);
	if (priv->specific_connection || !num_added) {
		gtk_widget_hide (widget);
	} else {
		g_signal_connect (widget, "changed",
		                  G_CALLBACK (connection_combo_changed), self);
	}
	if (gtk_tree_model_get_iter_first (priv->connection_model, &tree_iter))
		gtk_tree_model_get (priv->connection_model, &tree_iter, C_CON_COLUMN, &priv->connection, -1);

	return TRUE;
}

static void
device_combo_changed (GtkWidget *combo,
                      gpointer user_data)
{
	NMAWifiDialog *self = NMA_WIFI_DIALOG (user_data);
	NMAWifiDialogPrivate *priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);
	GtkTreeIter iter;
	GtkTreeModel *model;

	if (!gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter)) {
		g_warning ("%s: no active device combo box item.", __func__);
		return;
	}
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));

	g_object_unref (priv->device);
	gtk_tree_model_get (model, &iter, D_DEV_COLUMN, &priv->device, -1);

	if (!connection_combo_init (self)) {
		g_warning ("Couldn't change connection combo box.");
		return;
	}

	if (!security_combo_init (self, priv->secrets_only, NULL, NULL)) {
		g_warning ("Couldn't change Wi-Fi security combo box.");
		return;
	}

	security_combo_changed (priv->sec_combo, self);
}

static void
add_device_to_model (GtkListStore *model, NMDevice *device)
{
	GtkTreeIter iter;
	const char *desc;

	desc = nm_device_get_description (device);
	gtk_list_store_append (model, &iter);
	gtk_list_store_set (model, &iter, D_NAME_COLUMN, desc, D_DEV_COLUMN, device, -1);
}

static gboolean
can_use_device (NMDevice *device)
{
	/* Ignore unsupported devices */
	if (!(nm_device_get_capabilities (device) & NM_DEVICE_CAP_NM_SUPPORTED))
		return FALSE;

	if (!NM_IS_DEVICE_WIFI (device))
		return FALSE;

	if (nm_device_get_state (device) < NM_DEVICE_STATE_DISCONNECTED)
		return FALSE;

	return TRUE;
}

static gboolean
device_combo_init (NMAWifiDialog *self, NMDevice *device)
{
	NMAWifiDialogPrivate *priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);
	const GPtrArray *devices;
	GtkListStore *store;
	int i, num_added = 0;

	g_return_val_if_fail (priv->device == NULL, FALSE);

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_OBJECT);
	priv->device_model = GTK_TREE_MODEL (store);

	if (device) {
		if (!can_use_device (device))
			return FALSE;
		add_device_to_model (store, device);
		num_added++;
	} else {
		devices = nm_client_get_devices (priv->client);
		if (!devices)
			return FALSE;

		for (i = 0; devices && (i < devices->len); i++) {
			device = NM_DEVICE (g_ptr_array_index (devices, i));
			if (can_use_device (device)) {
				add_device_to_model (store, device);
				num_added++;
			}
		}
	}

	if (num_added > 0) {
		GtkWidget *widget;
		GtkTreeIter iter;

		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "device_combo"));
		gtk_combo_box_set_model (GTK_COMBO_BOX (widget), priv->device_model);
		gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
		g_signal_connect (G_OBJECT (widget), "changed",
		                  G_CALLBACK (device_combo_changed), self);
		if (num_added == 1) {
			gtk_widget_hide (widget);
		}
		if (gtk_tree_model_get_iter_first (priv->device_model, &iter))
			gtk_tree_model_get (priv->device_model, &iter, D_DEV_COLUMN, &priv->device, -1);
	}

	return num_added > 0 ? TRUE : FALSE;
}

static gboolean
find_proto (NMSettingWirelessSecurity *sec, const char *item)
{
	guint32 i;

	for (i = 0; i < nm_setting_wireless_security_get_num_protos (sec); i++) {
		if (!strcmp (item, nm_setting_wireless_security_get_proto (sec, i)))
			return TRUE;
	}
	return FALSE;
}

static NMUtilsSecurityType
get_default_type_for_security (NMSettingWirelessSecurity *sec,
                               gboolean have_ap,
                               guint32 ap_flags,
                               guint32 dev_caps)
{
	const char *key_mgmt, *auth_alg;

	g_return_val_if_fail (sec != NULL, NMU_SEC_NONE);

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (sec);
	auth_alg = nm_setting_wireless_security_get_auth_alg (sec);

	/* No IEEE 802.1x */
	if (!strcmp (key_mgmt, "none"))
		return NMU_SEC_STATIC_WEP;

	if (!strcmp (key_mgmt, "owe"))
		return NMU_SEC_OWE;

	if (   !strcmp (key_mgmt, "ieee8021x")
	    && (!have_ap || (ap_flags & NM_802_11_AP_FLAGS_PRIVACY))) {
		if (auth_alg && !strcmp (auth_alg, "leap"))
			return NMU_SEC_LEAP;
		return NMU_SEC_DYNAMIC_WEP;
	}

	if (!strcmp (key_mgmt, "sae"))
		return NMU_SEC_SAE;

	if (   !strcmp (key_mgmt, "wpa-none")
	    || !strcmp (key_mgmt, "wpa-psk")) {
		if (!have_ap || (ap_flags & NM_802_11_AP_FLAGS_PRIVACY)) {
			if (find_proto (sec, "rsn"))
				return NMU_SEC_WPA2_PSK;
			else if (find_proto (sec, "wpa"))
				return NMU_SEC_WPA_PSK;
			else
				return NMU_SEC_WPA_PSK;
		}
	}

	if (   !strcmp (key_mgmt, "wpa-eap")
	    && (!have_ap || (ap_flags & NM_802_11_AP_FLAGS_PRIVACY))) {
			if (find_proto (sec, "rsn"))
				return NMU_SEC_WPA2_ENTERPRISE;
			else if (find_proto (sec, "wpa"))
				return NMU_SEC_WPA_ENTERPRISE;
			else
				return NMU_SEC_WPA_ENTERPRISE;
	}

	return NMU_SEC_INVALID;
}

static void
add_security_item (NMAWifiDialog *self,
                   NMAWs *ws,
                   GtkListStore *model,
                   GtkTreeIter *iter,
                   const char *text)
{
	g_signal_connect (ws, "ws-changed", G_CALLBACK (stuff_changed_cb), self);
	gtk_list_store_append (model, iter);
	gtk_list_store_set (model, iter,
	                    S_NAME_COLUMN, text,
	                    S_SEC_COLUMN, g_object_ref_sink (ws),
	                    -1);
	g_object_unref (ws);
}

static void
get_secrets_cb (GObject *object,
                GAsyncResult *result,
                gpointer user_data)
{
	GetSecretsInfo *info = user_data;
	NMRemoteConnection *connection = NM_REMOTE_CONNECTION (object);
	NMAWifiDialogPrivate *priv;
	GVariant *secrets;
	GVariantIter variant_iter;
	const char *setting_name;
	GVariant *setting_dict;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GError *error = NULL;
	gboolean current_secrets = FALSE;

	if (info->canceled)
		goto out;

	priv = NMA_WIFI_DIALOG_GET_PRIVATE (info->self);
	if (priv->secrets_info == info) {
		priv->secrets_info = NULL;

		/* Buttons should only be re-enabled if this secrets response is the
		 * in-progress one.
		 */
		gtk_dialog_set_response_sensitive (GTK_DIALOG (info->self), GTK_RESPONSE_CANCEL, TRUE);
		current_secrets = TRUE;
	}

	secrets = nm_remote_connection_get_secrets_finish (connection, result, &error);
	if (error) {
		g_warning ("%s: error getting connection secrets: (%d) %s",
		           __func__,
		           error ? error->code : -1,
		           error && error->message ? error->message : "(unknown)");
		goto out;
	}

	if (current_secrets)
		_set_ok_sensitive (info->self, TRUE, NULL);

	/* User might have changed the connection while the secrets call was in
	 * progress, so don't try to update the wrong connection with the secrets
	 * we just received.
	 */
	if (   (priv->connection != info->connection)
	    || !secrets)
		goto out;

	/* Try to update the connection's secrets; log errors but we don't care */
	g_variant_iter_init (&variant_iter, secrets);
	while (g_variant_iter_next (&variant_iter, "{&s@a{sv}}", &setting_name, &setting_dict)) {
		GError *update_error = NULL;

		if (!nm_connection_update_secrets (priv->connection,
		                                   setting_name,
		                                   setting_dict,
		                                   &update_error)) {
			g_warning ("%s: error updating connection secrets: (%d) %s",
			           __func__,
			           update_error ? update_error->code : -1,
			           update_error && update_error->message ? update_error->message : "(unknown)");
			g_clear_error (&update_error);
		}
		g_variant_unref (setting_dict);
	}

	/* Update each security method's UI elements with the new secrets */
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (priv->sec_combo));
	if (gtk_tree_model_get_iter_first (model, &iter)) {
		do {
			NMAWs *ws = NULL;

			gtk_tree_model_get (model, &iter, S_SEC_COLUMN, &ws, -1);
			if (ws) {
				nma_ws_update_secrets (ws, priv->connection);
				g_object_unref (ws);
			}
		} while (gtk_tree_model_iter_next (model, &iter));
	}

out:
	g_object_unref (info->connection);
	g_free (info);
}

static gboolean
allow_wep (void)
{
	/* Note to whoever uses this: this might go away! */
	return !!getenv ("NM_ALLOW_INSECURE_WEP");
}

static gboolean
security_valid (NMUtilsSecurityType sectype,
                NM80211Mode mode,
                NMDeviceWifiCapabilities wifi_caps,
                gboolean have_ap,
                NM80211ApFlags ap_flags,
                NM80211ApSecurityFlags ap_wpa,
                NM80211ApSecurityFlags ap_rsn)
{
	if (   !have_ap && !allow_wep()
	    && (sectype == NMU_SEC_STATIC_WEP || sectype == NMU_SEC_DYNAMIC_WEP)) {
		return FALSE;
	}

	switch (mode) {
	case NM_802_11_MODE_AP:
		if (sectype == NMU_SEC_SAE)
			return TRUE;
		return nm_utils_ap_mode_security_valid (sectype, wifi_caps);
	case NM_802_11_MODE_ADHOC:
	case NM_802_11_MODE_INFRA:
	default:
		return nm_utils_security_valid (sectype,
		                                wifi_caps,
		                                have_ap,
		                                (mode == NM_802_11_MODE_ADHOC),
		                                ap_flags, ap_wpa, ap_rsn);
	}
	g_assert_not_reached ();
}

static gboolean
security_combo_init (NMAWifiDialog *self, gboolean secrets_only,
                     const char *secrets_setting_name, const char *const*secrets_hints)
{
	NMAWifiDialogPrivate *priv;
	GtkListStore *sec_model;
	GtkTreeIter iter;
	guint32 ap_flags = 0;
	guint32 ap_wpa = 0;
	guint32 ap_rsn = 0;
	guint32 dev_caps;
	NMSettingWirelessSecurity *wsec = NULL;
	NMUtilsSecurityType default_type = NMU_SEC_NONE;
	NMWepKeyType wep_type = NM_WEP_KEY_TYPE_KEY;
	int active = -1;
	int item = 0;
	NMSettingWireless *s_wireless = NULL;
	NM80211Mode mode;
	const char *setting_name;

	g_return_val_if_fail (self != NULL, FALSE);

	priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);
	g_return_val_if_fail (priv->device != NULL, FALSE);
	g_return_val_if_fail (priv->sec_combo != NULL, FALSE);

	mode = (priv->operation == OP_CREATE_ADHOC) ? NM_802_11_MODE_ADHOC : NM_802_11_MODE_INFRA;

	/* The security options displayed are filtered based on device
	 * capabilities, and if provided, additionally by access point capabilities.
	 * If a connection is given, that connection's options should be selected
	 * by default.  If hints is non-empty only filter based on the setting
	 * keys on the hints list.
	 */
	dev_caps = nm_device_wifi_get_capabilities (NM_DEVICE_WIFI (priv->device));
	if (priv->ap != NULL) {
		ap_flags = nm_access_point_get_flags (priv->ap);
		ap_wpa = nm_access_point_get_wpa_flags (priv->ap);
		ap_rsn = nm_access_point_get_rsn_flags (priv->ap);
	}

	if (priv->connection) {
		const char *mode_str;

		s_wireless = nm_connection_get_setting_wireless (priv->connection);

		mode_str = nm_setting_wireless_get_mode (s_wireless);
		if (mode_str && !strcmp (mode_str, "adhoc"))
			mode = NM_802_11_MODE_ADHOC;
		else if (mode_str && !strcmp (mode_str, "ap"))
			mode = NM_802_11_MODE_AP;
		else
			mode = NM_802_11_MODE_INFRA;

		wsec = nm_connection_get_setting_wireless_security (priv->connection);

		if (wsec) {
			default_type = get_default_type_for_security (wsec, !!priv->ap, ap_flags, dev_caps);
			if (default_type == NMU_SEC_STATIC_WEP)
				wep_type = nm_setting_wireless_security_get_wep_key_type (wsec);
			if (wep_type == NM_WEP_KEY_TYPE_UNKNOWN)
				wep_type = NM_WEP_KEY_TYPE_KEY;
		}
	} else if (mode == NM_802_11_MODE_ADHOC) {
		default_type = NMU_SEC_WPA2_PSK;
		wep_type = NM_WEP_KEY_TYPE_PASSPHRASE;
	}

	sec_model = gtk_list_store_new (2, G_TYPE_STRING, NMA_TYPE_WS);

	if (security_valid (NMU_SEC_NONE, mode, dev_caps, !!priv->ap, ap_flags, ap_wpa, ap_rsn)) {
		gtk_list_store_append (sec_model, &iter);
		gtk_list_store_set (sec_model, &iter,
		                    S_NAME_COLUMN, C_("Wifi/wired security", "None"),
		                    -1);
		if (default_type == NMU_SEC_NONE)
			active = item;
		item++;
	}

	/* Don't show Static WEP if both the AP and the device are capable of WPA,
	 * even though technically it's possible to have this configuration.
	 */
	if (   security_valid (NMU_SEC_STATIC_WEP, mode, dev_caps, !!priv->ap, ap_flags, ap_wpa, ap_rsn)
	    && ((!ap_wpa && !ap_rsn) || !(dev_caps & (NM_WIFI_DEVICE_CAP_WPA | NM_WIFI_DEVICE_CAP_RSN)))) {
		NMAWsWepKey *ws_wep;

		ws_wep = nma_ws_wep_key_new (priv->connection, NM_WEP_KEY_TYPE_KEY, mode == NM_802_11_MODE_ADHOC, secrets_only);
		add_security_item (self, NMA_WS (ws_wep), sec_model,
		                   &iter, _("WEP 40/128-bit Key (Hex or ASCII)"));
		if ((active < 0) && (default_type == NMU_SEC_STATIC_WEP) && (wep_type == NM_WEP_KEY_TYPE_KEY))
			active = item;
		item++;

		ws_wep = nma_ws_wep_key_new (priv->connection, NM_WEP_KEY_TYPE_PASSPHRASE, mode == NM_802_11_MODE_ADHOC, secrets_only);
		add_security_item (self, NMA_WS (ws_wep), sec_model,
		                   &iter, _("WEP 128-bit Passphrase"));
		if ((active < 0) && (default_type == NMU_SEC_STATIC_WEP) && (wep_type == NM_WEP_KEY_TYPE_PASSPHRASE))
			active = item;
		item++;
	}

	/* Don't show LEAP if both the AP and the device are capable of WPA,
	 * even though technically it's possible to have this configuration.
	 */
	if (   security_valid (NMU_SEC_LEAP, mode, dev_caps, !!priv->ap, ap_flags, ap_wpa, ap_rsn)
	    && ((!ap_wpa && !ap_rsn) || !(dev_caps & (NM_WIFI_DEVICE_CAP_WPA | NM_WIFI_DEVICE_CAP_RSN)))) {
		NMAWsLeap *ws_leap;

		ws_leap = nma_ws_leap_new (priv->connection, secrets_only);
		add_security_item (self, NMA_WS (ws_leap), sec_model,
		                   &iter, _("LEAP"));
		if ((active < 0) && (default_type == NMU_SEC_LEAP))
			active = item;
		item++;
	}

	if (security_valid (NMU_SEC_DYNAMIC_WEP, mode, dev_caps, !!priv->ap, ap_flags, ap_wpa, ap_rsn)) {
		NMAWsDynamicWep *ws_dynamic_wep;

		ws_dynamic_wep = nma_ws_dynamic_wep_new (priv->connection, FALSE, secrets_only);
		add_security_item (self, NMA_WS (ws_dynamic_wep), sec_model,
		                   &iter, _("Dynamic WEP (802.1x)"));
		if ((active < 0) && (default_type == NMU_SEC_DYNAMIC_WEP))
			active = item;
		item++;
	}

	if (   security_valid (NMU_SEC_WPA_PSK, mode, dev_caps, !!priv->ap, ap_flags, ap_wpa, ap_rsn)
	    || security_valid (NMU_SEC_WPA2_PSK, mode, dev_caps, !!priv->ap, ap_flags, ap_wpa, ap_rsn)) {
		NMAWsWpaPsk *ws_wpa_psk;

		ws_wpa_psk = nma_ws_wpa_psk_new (priv->connection, secrets_only);
		add_security_item (self, NMA_WS (ws_wpa_psk), sec_model,
		                   &iter, _("WPA & WPA2 Personal"));
		if ((active < 0) && ((default_type == NMU_SEC_WPA_PSK) || (default_type == NMU_SEC_WPA2_PSK)))
			active = item;
		item++;
	}

	if (   security_valid (NMU_SEC_WPA_ENTERPRISE, mode, dev_caps, !!priv->ap, ap_flags, ap_wpa, ap_rsn)
	    || security_valid (NMU_SEC_WPA2_ENTERPRISE, mode, dev_caps, !!priv->ap, ap_flags, ap_wpa, ap_rsn)) {
		NMAWsWpaEap *ws_wpa_eap;
		const char *const*hints = NULL;

		if (secrets_setting_name && !strcmp (secrets_setting_name, NM_SETTING_802_1X_SETTING_NAME))
			hints = secrets_hints;

		ws_wpa_eap = nma_ws_wpa_eap_new (priv->connection, FALSE, secrets_only, hints);
		add_security_item (self, NMA_WS (ws_wpa_eap), sec_model,
		                   &iter, _("WPA & WPA2 Enterprise"));
		if ((active < 0) && ((default_type == NMU_SEC_WPA_ENTERPRISE) || (default_type == NMU_SEC_WPA2_ENTERPRISE)))
			active = item;
		item++;
	}

	if (security_valid (NMU_SEC_SAE, mode, dev_caps, !!priv->ap, ap_flags, ap_wpa, ap_rsn)) {
		NMAWsSae *ws_sae;

		ws_sae = nma_ws_sae_new (priv->connection, secrets_only);
		add_security_item (self, NMA_WS (ws_sae), sec_model,
		                   &iter, _("WPA3 Personal"));
		if (active < 0 && default_type == NMU_SEC_SAE)
			active = item;
		item++;
	}

	if (security_valid (NMU_SEC_OWE, mode, dev_caps, !!priv->ap, ap_flags, ap_wpa, ap_rsn)) {
		NMAWsOwe *ws_owe;

		ws_owe = nma_ws_owe_new (priv->connection);
		add_security_item (self, NMA_WS (ws_owe), sec_model,
		                   &iter, _("Enhanced Open"));
		if (active < 0 && default_type == NMU_SEC_OWE)
			active = item;
		item++;
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX (priv->sec_combo), GTK_TREE_MODEL (sec_model));
	gtk_combo_box_set_active (GTK_COMBO_BOX (priv->sec_combo), active < 0 ? 0 : (guint32) active);
	g_object_unref (G_OBJECT (sec_model));

	/* If the dialog was given a connection when it was created, that connection
	 * will already be populated with secrets.  If no connection was given,
	 * then we need to get any existing secrets to populate the dialog with.
	 */
	if (priv->connection) {
		if (secrets_setting_name)
			setting_name = secrets_setting_name;
		else
			setting_name = nm_connection_need_secrets (priv->connection, NULL);
	} else
		setting_name = NULL;

	if (setting_name && NM_IS_REMOTE_CONNECTION (priv->connection)) {
		GetSecretsInfo *info;

		/* Desensitize the dialog's buttons while we wait for the secrets
		 * operation to complete.
		 */
		_set_ok_sensitive (self, FALSE, NULL);
		gtk_dialog_set_response_sensitive (GTK_DIALOG (self), GTK_RESPONSE_CANCEL, FALSE);

		info = g_malloc0 (sizeof (GetSecretsInfo));
		info->self = self;
		info->connection = g_object_ref (priv->connection);
		priv->secrets_info = info;

		nm_remote_connection_get_secrets_async (NM_REMOTE_CONNECTION (priv->connection),
		                                        setting_name, NULL, get_secrets_cb, info);
	}

	return TRUE;
}

static gboolean
revalidate (gpointer user_data)
{
	NMAWifiDialog *self = NMA_WIFI_DIALOG (user_data);
	NMAWifiDialogPrivate *priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);

	priv->revalidate_id = 0;
	security_combo_changed (priv->sec_combo, self);
	return FALSE;
}

static gboolean
internal_init (NMAWifiDialog *self,
               NMConnection *specific_connection,
               NMDevice *specific_device,
               gboolean secrets_only,
               const char *secrets_setting_name,
               const char *const*secrets_hints)
{
	NMAWifiDialogPrivate *priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);
	GtkWidget *widget;
	char *label, *icon_name = "network-wireless";
	gboolean security_combo_focus = FALSE;

	gtk_window_set_default_size (GTK_WINDOW (self), 488, -1);
	gtk_window_set_resizable (GTK_WINDOW (self), FALSE);

	priv->secrets_only = secrets_only;
	if (secrets_only)
		icon_name = "dialog-password";
	else
		icon_name = "network-wireless";

	if (specific_connection)
		priv->specific_connection = g_object_ref (specific_connection);

	gtk_window_set_icon_name (GTK_WINDOW (self), icon_name);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "image1"));
#if GTK_CHECK_VERSION(4,0,0)
	gtk_image_set_from_icon_name (GTK_IMAGE (widget), icon_name);
#else
	gtk_image_set_from_icon_name (GTK_IMAGE (widget), icon_name, GTK_ICON_SIZE_DIALOG);
#endif

	gtk_box_set_spacing (GTK_BOX (gtk_dialog_get_content_area (GTK_DIALOG (self))), 2);

	widget = gtk_dialog_add_button (GTK_DIALOG (self), _("_Cancel"), GTK_RESPONSE_CANCEL);

	/* Connect/Create button */
	if (priv->operation == OP_CREATE_ADHOC) {
		widget = gtk_dialog_add_button (GTK_DIALOG (self), _("C_reate"), GTK_RESPONSE_OK);
	} else {
		widget = gtk_dialog_add_button (GTK_DIALOG (self), _("C_onnect"), GTK_RESPONSE_OK);
		priv->ok_response_button = widget;
	}

#if !GTK_CHECK_VERSION(4,0,0)
	g_object_set (G_OBJECT (widget), "can-default", TRUE, NULL);
	gtk_widget_grab_default (widget);
#endif

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "wifi_dialog"));
	if (!widget) {
		g_warning ("Couldn't find Wi-Fi_dialog widget.");
		return FALSE;
	}

	gtk_box_append (GTK_BOX (gtk_dialog_get_content_area (GTK_DIALOG (self))), widget);

	/* If given a valid connection, hide the SSID bits and connection combo */
	if (specific_connection) {
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "network_name_entry"));
		gtk_widget_hide (widget);

		security_combo_focus = TRUE;
		priv->network_name_focus = FALSE;
	} else {
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "network_name_entry"));
		g_signal_connect (G_OBJECT (widget), "changed", (GCallback) ssid_entry_changed, self);
		priv->network_name_focus = TRUE;
	}

	_set_ok_sensitive (self, FALSE, NULL);

	if (!device_combo_init (self, specific_device)) {
		g_warning ("No Wi-Fi devices available.");
		return FALSE;
	}

	if (!connection_combo_init (self)) {
		g_warning ("Couldn't set up connection combo box.");
		return FALSE;
	}

	if (!security_combo_init (self, priv->secrets_only, secrets_setting_name, secrets_hints)) {
		g_warning ("Couldn't set up Wi-Fi security combo box.");
		return FALSE;
	}

	security_combo_changed (priv->sec_combo, self);
	g_signal_connect (G_OBJECT (priv->sec_combo), "changed",
	                  G_CALLBACK (security_combo_changed_manually), self);

	if (secrets_only) {
		gtk_widget_hide (priv->sec_combo);
	}

	if (security_combo_focus && !secrets_only)
		gtk_widget_grab_focus (priv->sec_combo);
	else if (priv->network_name_focus) {
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "network_name_entry"));
		gtk_widget_grab_focus (widget);
	}

	if (priv->connection) {
		char *tmp;
		char *esc_ssid = NULL;
		NMSettingWireless *s_wireless;
		GBytes *ssid;

		s_wireless = nm_connection_get_setting_wireless (priv->connection);
		ssid = s_wireless ? nm_setting_wireless_get_ssid (s_wireless) : NULL;
		if (ssid)
			esc_ssid = nm_utils_ssid_to_utf8 (g_bytes_get_data (ssid, NULL), g_bytes_get_size (ssid));

		tmp = g_strdup_printf (_("Passwords or encryption keys are required to access the Wi-Fi network “%s”."),
		                       esc_ssid ? esc_ssid : "<unknown>");
		gtk_window_set_title (GTK_WINDOW (self), _("Wi-Fi Network Authentication Required"));
		label = g_markup_printf_escaped ("<span size=\"larger\" weight=\"bold\">%s</span>\n\n%s",
		                                 _("Authentication required by Wi-Fi network"),
		                                 tmp);
		g_free (esc_ssid);
		g_free (tmp);
	} else if (priv->operation == OP_CREATE_ADHOC) {
		gtk_window_set_title (GTK_WINDOW (self), _("Create New Wi-Fi Network"));
		label = g_strdup_printf ("<span size=\"larger\" weight=\"bold\">%s</span>\n\n%s",
		                         _("New Wi-Fi network"),
		                         _("Enter a name for the Wi-Fi network you wish to create."));
	} else if (priv->operation == OP_CONNECT_HIDDEN) {
		gtk_window_set_title (GTK_WINDOW (self), _("Connect to Hidden Wi-Fi Network"));
		label = g_strdup_printf ("<span size=\"larger\" weight=\"bold\">%s</span>\n\n%s",
		                         _("Hidden Wi-Fi network"),
		                         _("Enter the name and security details of the hidden Wi-Fi network you wish to connect to."));
	} else
		g_assert_not_reached ();

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "caption_label"));
	gtk_label_set_markup (GTK_LABEL (widget), label);
	g_free (label);

	/* Re-validate from an idle handler so that widgets like file choosers
	 * have had time to find their files.
	 */
	priv->revalidate_id = g_idle_add (revalidate, self);

	return TRUE;
}

/**
 * nma_wifi_dialog_get_connection:
 * @self: an #NMAWifiDialog
 * @device: (out):
 * @ap: (out):
 *
 * Returns: (transfer full):
 */
NMConnection *
nma_wifi_dialog_get_connection (NMAWifiDialog *self,
                                NMDevice **device,
                                NMAccessPoint **ap)
{
	NMAWifiDialogPrivate *priv;
	GtkWidget *combo;
	GtkTreeModel *model;
	NMAWs *ws = NULL;
	GtkTreeIter iter;
	NMConnection *connection;
	NMSettingWireless *s_wireless;

	g_return_val_if_fail (self != NULL, NULL);

	priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);

	if (!priv->connection) {
		NMSettingConnection *s_con;
		char *uuid;
		GBytes *ssid;

		connection = nm_simple_connection_new ();

		s_con = (NMSettingConnection *) nm_setting_connection_new ();
		uuid = nm_utils_uuid_generate ();
		g_object_set (s_con,
			      NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
			      NM_SETTING_CONNECTION_UUID, uuid,
			      NULL);
		g_free (uuid);
		nm_connection_add_setting (connection, (NMSetting *) s_con);

		s_wireless = (NMSettingWireless *) nm_setting_wireless_new ();
		ssid = validate_dialog_ssid (self);
		g_object_set (s_wireless, NM_SETTING_WIRELESS_SSID, ssid, NULL);
		g_bytes_unref (ssid);

		if (priv->operation == OP_CREATE_ADHOC) {
			NMSetting *s_ip4;

			g_object_set (s_wireless, NM_SETTING_WIRELESS_MODE, "adhoc", NULL);

			s_ip4 = nm_setting_ip4_config_new ();
			g_object_set (s_ip4,
			              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_SHARED,
			              NULL);
			nm_connection_add_setting (connection, s_ip4);
		} else if (priv->operation == OP_CONNECT_HIDDEN) {
			/* Mark as a hidden SSID network */
			g_object_set (s_wireless, NM_SETTING_WIRELESS_HIDDEN, TRUE, NULL);
		} else
			g_assert_not_reached ();

		nm_connection_add_setting (connection, (NMSetting *) s_wireless);
	} else
		connection = g_object_ref (priv->connection);

	/* Fill security */
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (priv->sec_combo));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (priv->sec_combo), &iter))
		gtk_tree_model_get (model, &iter, S_SEC_COLUMN, &ws, -1);
	if (ws) {
		nma_ws_fill_connection (ws, connection);
		g_object_unref (ws);
	}

	/* Save new CA cert ignore values to GSettings */
	nma_eap_ca_cert_ignore_save (connection);

	/* Fill device */
	if (device) {
		combo = GTK_WIDGET (gtk_builder_get_object (priv->builder, "device_combo"));
		gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter);
		gtk_tree_model_get (priv->device_model, &iter, D_DEV_COLUMN, device, -1);
		g_object_unref (*device);
	}

	if (ap)
		*ap = priv->ap;

	return connection;
}

static GtkWidget *
internal_new_dialog (NMClient *client,
                     NMConnection *connection,
                     NMDevice *device,
                     NMAccessPoint *ap,
                     gboolean secrets_only,
                     const char *secrets_setting_name,
                     const char *const*secrets_hints)
{
	NMAWifiDialog *self;
	NMAWifiDialogPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	self = NMA_WIFI_DIALOG (g_object_new (NMA_TYPE_WIFI_DIALOG, NULL));
	if (self) {
		priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);

		priv->client = g_object_ref (client);
		if (ap)
			priv->ap = g_object_ref (ap);

		priv->sec_combo = GTK_WIDGET (gtk_builder_get_object (priv->builder, "security_combo"));
		priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

		/* Handle CA cert ignore stuff */
		nma_eap_ca_cert_ignore_load (connection);

		if (!internal_init (self, connection, device, secrets_only, secrets_setting_name, secrets_hints)) {
			g_warning ("Couldn't create Wi-Fi security dialog.");
			gtk_window_destroy (GTK_WINDOW (self));
			self = NULL;
		}
	}

	return GTK_WIDGET (self);
}

/**
 * nma_wifi_dialog_new:
 * @client: client to retrieve list of devices or connections from
 * @connection: connection to be shown/edited or %NULL
 * @device: device to check connection compatibility against
 * @ap: AP to check connection compatibility against
 * @secrets_only: whether to only ask for secrets for given connection
 *
 * Creates a wifi connection dialog and populates it with settings from
 * @connection if given.  If @device is not given a device selection combo box
 * will be included.  If @connection is not given a connection selection combo
 * box will be included.  If @secrets_only is %FALSE a complete connection
 * creator/editor dialog is returned, otherwise only wifi security secrets
 * relevant to the security settings in @connection are going to be shown and
 * will be editable.
 *
 * Returns: the dialog widget or %NULL in case of error
 */
GtkWidget *
nma_wifi_dialog_new (NMClient *client,
                     NMConnection *connection,
                     NMDevice *device,
                     NMAccessPoint *ap,
                     gboolean secrets_only)
{
	guint32 dev_caps;

	/* Ensure device validity */
	if (device) {
		dev_caps = nm_device_get_capabilities (device);
		g_return_val_if_fail (dev_caps & NM_DEVICE_CAP_NM_SUPPORTED, NULL);
		g_return_val_if_fail (NM_IS_DEVICE_WIFI (device), NULL);
	}

	return internal_new_dialog (client,
	                            connection,
	                            device,
	                            ap,
	                            secrets_only,
	                            NULL,
	                            NULL);
}

/**
 * nma_wifi_dialog_new_for_secrets:
 * @client: client to retrieve list of devices or connections from
 * @connection: connection for which secrets are requested
 * @secrets_setting_name: setting name whose secrets are requested
 *   or %NULL
 * @secrets_hints: array of setting key names within the setting given in
 *   @secrets_setting_name which are requested or %NULL
 *
 * Creates a wifi secrets dialog and populates it with setting values from
 * @connection.  If @secrets_setting_name and @secrets_hints are not given
 * this function creates an identical dialog as nma_wifi_dialog_new() would
 * create with the @secrets_only parameter %TRUE.  Otherwise
 * @secrets_setting_name and @secrets_hints determine the list of specific
 * secrets that are being requested from the user and no editable entries
 * are shown for any other settings.
 *
 * Note: only a subset of all settings and setting keys is supported as
 * @secrets_setting_name and @secrets_hints.
 *
 * Returns: the dialog widget or %NULL in case of error
 */
GtkWidget *
nma_wifi_dialog_new_for_secrets (NMClient *client,
                                 NMConnection *connection,
                                 const char *secrets_setting_name,
                                 const char *const*secrets_hints)
{
	return internal_new_dialog (client,
	                            connection,
	                            NULL,
	                            NULL,
	                            TRUE,
	                            secrets_setting_name,
	                            secrets_hints);
}

static GtkWidget *
internal_new_operation (NMClient *client,
                        guint operation)
{
	NMAWifiDialog *self;
	NMAWifiDialogPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	self = NMA_WIFI_DIALOG (g_object_new (NMA_TYPE_WIFI_DIALOG, NULL));
	if (!self)
		return NULL;

	priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);

	priv->client = g_object_ref (client);
	priv->sec_combo = GTK_WIDGET (gtk_builder_get_object (priv->builder, "security_combo"));
	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);
	priv->operation = operation;

	if (!internal_init (self, NULL, NULL, FALSE, NULL, NULL)) {
		g_warning ("Couldn't create Wi-Fi security dialog.");
		gtk_window_destroy (GTK_WINDOW (self));
		return NULL;
	}

	return GTK_WIDGET (self);
}

GtkWidget *
nma_wifi_dialog_new_for_hidden (NMClient *client)
{
	return internal_new_operation (client, OP_CONNECT_HIDDEN);
}

GtkWidget *
nma_wifi_dialog_new_for_other (NMClient *client)
{
	return internal_new_operation (client, OP_CONNECT_HIDDEN);
}

GtkWidget *
nma_wifi_dialog_new_for_create (NMClient *client)
{
	return internal_new_operation (client, OP_CREATE_ADHOC);
}

/**
 * nma_wifi_dialog_nag_user:
 * @self:
 *
 * Returns: (transfer full):
 */
GtkWidget *
nma_wifi_dialog_nag_user (NMAWifiDialog *self)
{
	return NULL;
}

static void
nma_wifi_dialog_init (NMAWifiDialog *self)
{
	NMAWifiDialogPrivate *priv = NMA_WIFI_DIALOG_GET_PRIVATE (self);
	GError *error = NULL;

	priv->builder = gtk_builder_new ();

	if (!gtk_builder_add_from_resource (priv->builder, "/org/gnome/libnma/wifi.ui", &error)) {
		g_warning ("Couldn't load builder resource: %s", error->message);
		g_error_free (error);
	}
}

static void
dispose (GObject *object)
{
	NMAWifiDialogPrivate *priv = NMA_WIFI_DIALOG_GET_PRIVATE (object);


	if (priv->secrets_info) {
		priv->secrets_info->canceled = TRUE;
		priv->secrets_info = NULL;
	}

	g_clear_object (&priv->client);
	g_clear_object (&priv->builder);

	g_clear_object (&priv->device_model);
	g_clear_object (&priv->connection_model);

	g_clear_object (&priv->group);

	g_clear_object (&priv->specific_connection);
	g_clear_object (&priv->connection);

	g_clear_object (&priv->device);

	g_clear_object (&priv->ap);

	if (priv->revalidate_id) {
		g_source_remove (priv->revalidate_id);
		priv->revalidate_id = 0;
	}

	G_OBJECT_CLASS (nma_wifi_dialog_parent_class)->dispose (object);
}

static void
nma_wifi_dialog_class_init (NMAWifiDialogClass *nmad_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (nmad_class);

	g_type_class_add_private (nmad_class, sizeof (NMAWifiDialogPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
}
