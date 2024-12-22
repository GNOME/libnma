// SPDX-License-Identifier: GPL-2.0+
/*
 * EAP-FAST authentication method (RFC4851)
 *
 * Copyright (C) 2012 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <string.h>

#include "nma-eap.h"
#include "nma-ws.h"
#include "nma-ws-private.h"
#include "utils.h"

#define I_NAME_COLUMN   0
#define I_METHOD_COLUMN 1

struct _NMAEapFast {
	NMAEap parent;

	const char *password_flags_name;
	GtkSizeGroup *size_group;
	NMAWs8021x *ws_8021x;
	gboolean is_editor;
	GtkWidget *eap_widget;
	char *pac_file_name;
};

static void
destroy (NMAEap *parent)
{
	NMAEapFast *method = (NMAEapFast *) parent;

	if (method->size_group)
		g_object_unref (method->size_group);
}

static gboolean
validate (NMAEap *parent, GError **error)
{
	NMAEapFast *method = (NMAEapFast *) parent;
	GtkWidget *widget;
	GtkTreeModel *model;
	GtkTreeIter iter;
	NMAEap *eap = NULL;
	gboolean provisioning;
	gboolean valid = TRUE;

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_provision_checkbutton"));
	g_assert (widget);
	provisioning = gtk_check_button_get_active (GTK_CHECK_BUTTON (widget));
	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_file_button"));
	g_assert (widget);
	if (!provisioning && !method->pac_file_name) {
		widget_set_error (widget);
		g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("missing EAP-FAST PAC file"));
		valid = FALSE;
	} else
		widget_unset_error (widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_inner_auth_combo"));
	g_assert (widget);
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	gtk_tree_model_get (model, &iter, I_METHOD_COLUMN, &eap, -1);
	g_assert (eap);
	valid = nma_eap_validate (eap, valid ? error : NULL) && valid;
	nma_eap_unref (eap);
	return valid;
}

static void
add_to_size_group (NMAEap *parent, GtkSizeGroup *group)
{
	NMAEapFast *method = (NMAEapFast *) parent;
	GtkWidget *widget;
	GtkTreeModel *model;
	GtkTreeIter iter;
	NMAEap *eap;

	if (method->size_group)
		g_object_unref (method->size_group);
	method->size_group = g_object_ref (group);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_anon_identity_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_file_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_provision_checkbutton"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_inner_auth_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_inner_auth_combo"));
	g_assert (widget);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	gtk_tree_model_get (model, &iter, I_METHOD_COLUMN, &eap, -1);
	g_assert (eap);
	nma_eap_add_to_size_group (eap, group);
	nma_eap_unref (eap);
}

static void
fill_connection (NMAEap *parent, NMConnection *connection)
{
	NMAEapFast *method = (NMAEapFast *) parent;
	NMSetting8021x *s_8021x;
	GtkWidget *widget;
	const char *text;
	NMAEap *eap = NULL;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gboolean enabled;
	int pac_provisioning = 0;

	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);

	nm_setting_802_1x_add_eap_method (s_8021x, "fast");

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_anon_identity_entry"));
	g_assert (widget);
	text = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (text && *text)
		g_object_set (s_8021x, NM_SETTING_802_1X_ANONYMOUS_IDENTITY, text, NULL);

	g_object_set (s_8021x, NM_SETTING_802_1X_PAC_FILE, method->pac_file_name, NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_provision_checkbutton"));
	enabled = gtk_check_button_get_active (GTK_CHECK_BUTTON (widget));

	if (!enabled)
		g_object_set (G_OBJECT (s_8021x), NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING, "0", NULL);
	else {
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_provision_combo"));
		pac_provisioning = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));

		switch (pac_provisioning) {
		case 0:  /* Anonymous */
			g_object_set (G_OBJECT (s_8021x), NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING, "1", NULL);
			break;
		case 1:  /* Authenticated */
			g_object_set (G_OBJECT (s_8021x), NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING, "2", NULL);
			break;
		case 2:  /* Both - anonymous and authenticated */
			g_object_set (G_OBJECT (s_8021x), NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING, "3", NULL);
			break;
		default: /* Should not happen */
			g_object_set (G_OBJECT (s_8021x), NM_SETTING_802_1X_PHASE1_FAST_PROVISIONING, "1", NULL);
			break;
		}
	}

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_inner_auth_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	gtk_tree_model_get (model, &iter, I_METHOD_COLUMN, &eap, -1);
	g_assert (eap);

	nma_eap_fill_connection (eap, connection);
	nma_eap_unref (eap);
}

static void
inner_auth_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	NMAEap *parent = (NMAEap *) user_data;
	NMAEapFast *method = (NMAEapFast *) parent;
	GtkBox *vbox;
	NMAEap *eap = NULL;
	GtkTreeModel *model;
	GtkTreeIter iter;

	vbox = GTK_BOX (gtk_builder_get_object (parent->builder, "eap_fast_inner_auth_vbox"));
	g_assert (vbox);

	/* Remove any previous wireless security widgets */
	if (method->eap_widget)
		gtk_box_remove (vbox, method->eap_widget);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter);
	gtk_tree_model_get (model, &iter, I_METHOD_COLUMN, &eap, -1);
	g_assert (eap);

	method->eap_widget = nma_eap_get_widget (eap);
	g_return_if_fail (method->eap_widget);
	gtk_widget_unparent (method->eap_widget);

	if (method->size_group)
		nma_eap_add_to_size_group (eap, method->size_group);
	gtk_box_append (vbox, method->eap_widget);

	nma_eap_unref (eap);

	nma_ws_changed_cb (combo, method->ws_8021x);
}

static GtkWidget *
inner_auth_combo_init (NMAEapFast *method,
                       NMConnection *connection,
                       NMSetting8021x *s_8021x,
                       gboolean secrets_only)
{
	NMAEap *parent = (NMAEap *) method;
	GtkWidget *combo;
	GtkListStore *auth_model;
	GtkTreeIter iter;
	NMAEapSimple *em_gtc;
	NMAEapSimple *em_mschap_v2;
	guint32 active = 0;
	const char *phase2_auth = NULL;
	NMAEapSimpleFlags simple_flags;

	auth_model = gtk_list_store_new (2, G_TYPE_STRING, nma_eap_get_type ());

	if (s_8021x) {
		if (nm_setting_802_1x_get_phase2_auth (s_8021x))
			phase2_auth = nm_setting_802_1x_get_phase2_auth (s_8021x);
		else if (nm_setting_802_1x_get_phase2_autheap (s_8021x))
			phase2_auth = nm_setting_802_1x_get_phase2_autheap (s_8021x);
	}

	simple_flags = NMA_EAP_SIMPLE_FLAG_PHASE2;
	if (method->is_editor)
		simple_flags |= NMA_EAP_SIMPLE_FLAG_IS_EDITOR;
	if (secrets_only)
		simple_flags |= NMA_EAP_SIMPLE_FLAG_SECRETS_ONLY;

	em_gtc = nma_eap_simple_new (method->ws_8021x,
	                                connection,
	                                NMA_EAP_SIMPLE_TYPE_GTC,
	                                simple_flags,
	                                NULL);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    I_NAME_COLUMN, _("GTC"),
	                    I_METHOD_COLUMN, em_gtc,
	                    -1);
	nma_eap_unref (NMA_EAP (em_gtc));

	/* Check for defaulting to GTC */
	if (phase2_auth && !strcasecmp (phase2_auth, "gtc"))
		active = 0;

	em_mschap_v2 = nma_eap_simple_new (method->ws_8021x,
	                                      connection,
	                                      NMA_EAP_SIMPLE_TYPE_MSCHAP_V2,
	                                      simple_flags,
	                                      NULL);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    I_NAME_COLUMN, _("MSCHAPv2"),
	                    I_METHOD_COLUMN, em_mschap_v2,
	                    -1);
	nma_eap_unref (NMA_EAP (em_mschap_v2));

	/* Check for defaulting to MSCHAPv2 */
	if (phase2_auth && !strcasecmp (phase2_auth, "mschapv2"))
		active = 1;

	combo = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_inner_auth_combo"));
	g_assert (combo);

	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (auth_model));
	g_object_unref (G_OBJECT (auth_model));
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), active);
	return combo;
}

static void
update_secrets (NMAEap *parent, NMConnection *connection)
{
	nma_eap_phase2_update_secrets_helper (parent,
	                                      connection,
	                                      "eap_fast_inner_auth_combo",
	                                      I_METHOD_COLUMN);
}

static void
update_pac_chooser_button_label (NMAEap *parent, GtkWidget *chooser)
{
	NMAEapFast *method = (NMAEapFast *) parent;
	GtkWidget *label;
	char *basename;

	label = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_file_button_label"));
	g_assert (label);

	if (method->pac_file_name) {
		basename = g_filename_display_basename (method->pac_file_name);
		gtk_label_set_text (GTK_LABEL (label), basename);
		g_free (basename);
	} else {
		gtk_label_set_text (GTK_LABEL (label), _("(None)"));
	}
}

static void
pac_chooser_clicked (GtkButton* self, gpointer user_data)
{
	NMAEap *parent = (NMAEap *) user_data;
	NMAEapFast *method = (NMAEapFast *) parent;
	GtkWidget *chooser;
	GFile *file;
	GtkRoot *toplevel;

	toplevel = gtk_widget_get_root (GTK_WIDGET (self));
	if (toplevel && !GTK_IS_WINDOW (toplevel))
		toplevel = NULL;

	chooser = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_file_chooser"));
	g_assert (chooser);

	gtk_window_set_transient_for (GTK_WINDOW (chooser), (GtkWindow *) toplevel);

	if (nma_gtk_dialog_run (GTK_DIALOG (chooser)) == GTK_RESPONSE_ACCEPT) {
		if (method->pac_file_name)
			g_clear_pointer (&method->pac_file_name, g_free);

		file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (chooser));
		if (file) {
			method->pac_file_name = g_file_get_path (file);
			g_object_unref (file);
		}

		update_pac_chooser_button_label (parent, chooser);
		nma_ws_changed_cb (NULL, method->ws_8021x);
	}
}

NMAEapFast *
nma_eap_fast_new (NMAWs8021x *ws_8021x,
                  NMConnection *connection,
                  gboolean is_editor,
                  gboolean secrets_only)
{
	NMAEap *parent;
	NMAEapFast *method;
	GtkWidget *widget;
	GtkFileFilter *filter;
	NMSetting8021x *s_8021x = NULL;
	GFile *file;
	gboolean provisioning_enabled = TRUE;

	parent = nma_eap_init (NMA_WS (ws_8021x),
	                       sizeof (NMAEapFast),
	                       validate,
	                       add_to_size_group,
	                       fill_connection,
	                       update_secrets,
	                       destroy,
	                       "/org/gnome/libnma/nma-eap-fast.ui",
	                       "eap_fast_grid",
	                       "eap_fast_anon_identity_entry",
	                       FALSE);
	if (!parent)
		return NULL;

	method = (NMAEapFast *) parent;
	method->password_flags_name = NM_SETTING_802_1X_PASSWORD;
	method->ws_8021x = ws_8021x;
	method->is_editor = is_editor;

	if (connection)
		s_8021x = nm_connection_get_setting_802_1x (connection);


	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_provision_combo"));
	g_assert (widget);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
	if (s_8021x) {
		const char *fast_prov;

		fast_prov = nm_setting_802_1x_get_phase1_fast_provisioning (s_8021x);
		if (fast_prov) {
			if (!strcmp (fast_prov, "0"))
				provisioning_enabled = FALSE;
			else if (!strcmp (fast_prov, "1"))
				gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
			else if (!strcmp (fast_prov, "2"))
				gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 1);
			else if (!strcmp (fast_prov, "3"))
				gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 2);
		}
	}
	gtk_widget_set_sensitive (widget, provisioning_enabled);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_provision_checkbutton"));
	gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), provisioning_enabled);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_anon_identity_entry"));
	if (s_8021x && nm_setting_802_1x_get_anonymous_identity (s_8021x))
		gtk_editable_set_text (GTK_EDITABLE (widget), nm_setting_802_1x_get_anonymous_identity (s_8021x));

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_file_button"));
	g_assert (widget);

	g_signal_connect (G_OBJECT (widget), "clicked",
	                  (GCallback) pac_chooser_clicked,
	                  parent);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_file_chooser"));
	g_assert (widget);

	filter = gtk_file_filter_new ();
	gtk_file_filter_add_pattern (filter, "*.pac");
	gtk_file_filter_set_name (filter, _("PAC files (*.pac)"));
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
	filter = gtk_file_filter_new ();
	gtk_file_filter_add_pattern (filter, "*");
	gtk_file_filter_set_name (filter, _("All files"));
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);

	if (connection && s_8021x) {
		method->pac_file_name = g_strdup (nm_setting_802_1x_get_pac_file (s_8021x));
		if (method->pac_file_name) {
			file = g_file_new_for_path (method->pac_file_name);
			gtk_file_chooser_set_file (GTK_FILE_CHOOSER (widget), file, NULL);
			g_object_unref (file);
		}
	}

	update_pac_chooser_button_label (parent, widget);

	widget = inner_auth_combo_init (method, connection, s_8021x, secrets_only);
	inner_auth_combo_changed_cb (widget, (gpointer) method);

	if (secrets_only) {
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_anon_identity_entry"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_provision_checkbutton"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_provision_combo"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_pac_file_button"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_fast_inner_auth_combo"));
		gtk_widget_hide (widget);
	}

	return method;
}
