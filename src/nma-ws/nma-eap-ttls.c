// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright (C) 2007 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <string.h>

#include "nma-eap.h"
#include "nma-ws.h"
#include "nma-ws-private.h"
#include "nma-cert-chooser.h"
#include "utils.h"

#define I_NAME_COLUMN   0
#define I_METHOD_COLUMN 1

struct _NMAEapTtls {
	NMAEap parent;

	const char *password_flags_name;
	GtkSizeGroup *size_group;
	NMAWs8021x *ws_8021x;
	gboolean is_editor;

	GtkWidget *ca_cert_chooser;
	GtkWidget *eap_widget;
};

static void
destroy (NMAEap *parent)
{
	NMAEapTtls *method = (NMAEapTtls *) parent;

	if (method->size_group)
		g_object_unref (method->size_group);
}

static gboolean
validate (NMAEap *parent, GError **error)
{
	NMAEapTtls *method = (NMAEapTtls *) parent;
	GtkWidget *widget;
	GtkTreeModel *model;
	GtkTreeIter iter;
	NMAEap *eap = NULL;
	gboolean valid = FALSE;

	if (   gtk_widget_get_sensitive (method->ca_cert_chooser)
	    && !nma_cert_chooser_validate (NMA_CERT_CHOOSER (method->ca_cert_chooser), error))
		return FALSE;

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_inner_auth_combo"));
	g_assert (widget);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	gtk_tree_model_get (model, &iter, I_METHOD_COLUMN, &eap, -1);
	g_assert (eap);
	valid = nma_eap_validate (eap, error);
	nma_eap_unref (eap);
	return valid;
}

static void
add_to_size_group (NMAEap *parent, GtkSizeGroup *group)
{
	NMAEapTtls *method = (NMAEapTtls *) parent;
	GtkWidget *widget;
	GtkTreeModel *model;
	GtkTreeIter iter;
	NMAEap *eap;

	if (method->size_group)
		g_object_unref (method->size_group);
	method->size_group = g_object_ref (group);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_anon_identity_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_domain_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	nma_cert_chooser_add_to_size_group (NMA_CERT_CHOOSER (method->ca_cert_chooser), group);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_inner_auth_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_inner_auth_combo"));
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
	NMAEapTtls *method = (NMAEapTtls *) parent;
	NMSetting8021x *s_8021x;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	NMSettingSecretFlags secret_flags;
	GtkWidget *widget;
	const char *text;
	char *value = NULL;
	NMAEap *eap = NULL;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GError *error = NULL;
	NMSetting8021xCKScheme scheme = NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;
	gboolean ca_cert_error = FALSE;

	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);

	nm_setting_802_1x_add_eap_method (s_8021x, "ttls");

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_anon_identity_entry"));
	g_assert (widget);
	text = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (text && *text)
		g_object_set (s_8021x, NM_SETTING_802_1X_ANONYMOUS_IDENTITY, text, NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_domain_entry"));
	g_assert (widget);
	text = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (text && *text)
		g_object_set (s_8021x, NM_SETTING_802_1X_DOMAIN_SUFFIX_MATCH, text, NULL);

	/* Save CA certificate PIN and its flags to the connection */
	secret_flags = nma_cert_chooser_get_cert_password_flags (NMA_CERT_CHOOSER (method->ca_cert_chooser));
	nm_setting_set_secret_flags (NM_SETTING (s_8021x), NM_SETTING_802_1X_CA_CERT_PASSWORD,
	                             secret_flags, NULL);
	if (method->is_editor) {
		/* Update secret flags and popup when editing the connection */
		nma_cert_chooser_update_cert_password_storage (NMA_CERT_CHOOSER (method->ca_cert_chooser),
		                                               secret_flags, NM_SETTING (s_8021x),
		                                               NM_SETTING_802_1X_CA_CERT_PASSWORD);
		g_object_set (s_8021x, NM_SETTING_802_1X_CA_CERT_PASSWORD,
		              nma_cert_chooser_get_cert_password (NMA_CERT_CHOOSER (method->ca_cert_chooser)),
		              NULL);
	}

	/* TLS CA certificate */
	if (gtk_widget_get_sensitive (method->ca_cert_chooser))
		value = nma_cert_chooser_get_cert (NMA_CERT_CHOOSER (method->ca_cert_chooser), &scheme);
	format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	if (!nm_setting_802_1x_set_ca_cert (s_8021x, value, scheme, &format, &error)) {
		g_warning ("Couldn't read CA certificate '%s': %s", value, error ? error->message : "(unknown)");
		g_clear_error (&error);
		ca_cert_error = TRUE;
	}
	nma_eap_ca_cert_ignore_set (parent, connection, value, ca_cert_error);
	g_free (value);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_inner_auth_combo"));
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
	NMAEapTtls *method = (NMAEapTtls *) parent;
	GtkBox *vbox;
	NMAEap *eap = NULL;
	GtkTreeModel *model;
	GtkTreeIter iter;

	vbox = GTK_BOX (gtk_builder_get_object (parent->builder, "eap_ttls_inner_auth_vbox"));
	g_return_if_fail (vbox);

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
inner_auth_combo_init (NMAEapTtls *method,
                       NMConnection *connection,
                       NMSetting8021x *s_8021x,
                       gboolean secrets_only)
{
	NMAEap *parent = (NMAEap *) method;
	GtkWidget *combo;
	GtkListStore *auth_model;
	GtkTreeIter iter;
	NMAEapSimple *em_pap;
	NMAEapSimple *em_mschap;
	NMAEapSimple *em_mschap_v2;
	NMAEapSimple *em_plain_mschap_v2;
	NMAEapSimple *em_chap;
	NMAEapSimple *em_md5;
	NMAEapSimple *em_gtc;
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

	simple_flags = NMA_EAP_SIMPLE_FLAG_PHASE2 | NMA_EAP_SIMPLE_FLAG_AUTHEAP_ALLOWED;
	if (method->is_editor)
		simple_flags |= NMA_EAP_SIMPLE_FLAG_IS_EDITOR;
	if (secrets_only)
		simple_flags |= NMA_EAP_SIMPLE_FLAG_SECRETS_ONLY;

	em_pap = nma_eap_simple_new (method->ws_8021x,
	                             connection,
	                             NMA_EAP_SIMPLE_TYPE_PAP,
	                             simple_flags,
	                             NULL);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    I_NAME_COLUMN, _("PAP"),
	                    I_METHOD_COLUMN, em_pap,
	                    -1);
	nma_eap_unref (NMA_EAP (em_pap));

	/* Check for defaulting to PAP */
	if (phase2_auth && !strcasecmp (phase2_auth, "pap"))
		active = 0;

	em_mschap = nma_eap_simple_new (method->ws_8021x,
	                                connection,
	                                NMA_EAP_SIMPLE_TYPE_MSCHAP,
	                                simple_flags,
	                                NULL);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    I_NAME_COLUMN, _("MSCHAP"),
	                    I_METHOD_COLUMN, em_mschap,
	                    -1);
	nma_eap_unref (NMA_EAP (em_mschap));

	/* Check for defaulting to MSCHAP */
	if (phase2_auth && !strcasecmp (phase2_auth, "mschap"))
		active = 1;

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
	if (phase2_auth && !strcasecmp (phase2_auth, "mschapv2") &&
	    nm_setting_802_1x_get_phase2_autheap (s_8021x) != NULL)
		active = 2;

	em_plain_mschap_v2 = nma_eap_simple_new (method->ws_8021x,
	                                         connection,
	                                         NMA_EAP_SIMPLE_TYPE_PLAIN_MSCHAP_V2,
	                                         simple_flags,
	                                         NULL);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    I_NAME_COLUMN, _("MSCHAPv2 (no EAP)"),
	                    I_METHOD_COLUMN, em_plain_mschap_v2,
	                    -1);
	nma_eap_unref (NMA_EAP (em_plain_mschap_v2));

	/* Check for defaulting to plain MSCHAPv2 */
	if (phase2_auth && !strcasecmp (phase2_auth, "mschapv2") &&
	    nm_setting_802_1x_get_phase2_auth (s_8021x) != NULL)
		active = 3;

	em_chap = nma_eap_simple_new (method->ws_8021x,
	                              connection,
	                              NMA_EAP_SIMPLE_TYPE_CHAP,
	                              simple_flags,
	                              NULL);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    I_NAME_COLUMN, _("CHAP"),
	                    I_METHOD_COLUMN, em_chap,
	                    -1);
	nma_eap_unref (NMA_EAP (em_chap));

	/* Check for defaulting to CHAP */
	if (phase2_auth && !strcasecmp (phase2_auth, "chap"))
		active = 4;

	em_md5 = nma_eap_simple_new (method->ws_8021x,
	                             connection,
	                             NMA_EAP_SIMPLE_TYPE_MD5,
	                             simple_flags,
	                             NULL);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    I_NAME_COLUMN, _("MD5"),
	                    I_METHOD_COLUMN, em_md5,
	                    -1);
	nma_eap_unref (NMA_EAP (em_md5));

	/* Check for defaulting to MD5 */
	if (phase2_auth && !strcasecmp (phase2_auth, "md5"))
		active = 5;

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
		active = 6;

	combo = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_inner_auth_combo"));
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
	                                      "eap_ttls_inner_auth_combo",
	                                      I_METHOD_COLUMN);
}

NMAEapTtls *
nma_eap_ttls_new (NMAWs8021x *ws_8021x,
                     NMConnection *connection,
                     gboolean is_editor,
                     gboolean secrets_only)
{
	NMAEap *parent;
	NMAEapTtls *method;
	GtkWidget *widget;
	NMSetting8021x *s_8021x = NULL;
	gboolean ca_not_required = FALSE;

	parent = nma_eap_init (NMA_WS (ws_8021x),
	                       sizeof (NMAEapTtls),
	                       validate,
	                       add_to_size_group,
	                       fill_connection,
	                       update_secrets,
	                       destroy,
	                       "/org/gnome/libnma/nma-eap-ttls.ui",
	                       "eap_ttls_grid",
	                       "eap_ttls_anon_identity_entry",
	                       FALSE);
	if (!parent)
		return NULL;

	method = (NMAEapTtls *) parent;
	method->password_flags_name = NM_SETTING_802_1X_PASSWORD;
	method->ws_8021x = ws_8021x;
	method->is_editor = is_editor;

	if (connection)
		s_8021x = nm_connection_get_setting_802_1x (connection);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_grid"));
	g_assert (widget);

	method->ca_cert_chooser = nma_cert_chooser_new ("CA",
	                                                  NMA_CERT_CHOOSER_FLAG_CERT
	                                                | (secrets_only ? NMA_CERT_CHOOSER_FLAG_PASSWORDS : 0));
	gtk_grid_attach (GTK_GRID (widget), method->ca_cert_chooser, 0, 2, 2, 1);
	gtk_widget_show (method->ca_cert_chooser);

	g_signal_connect (method->ca_cert_chooser,
	                  "cert-validate",
	                  G_CALLBACK (nma_eap_ca_cert_validate_cb),
	                  NULL);
	g_signal_connect (method->ca_cert_chooser,
	                  "changed",
	                  G_CALLBACK (nma_ws_changed_cb),
	                  ws_8021x);

	nma_eap_setup_cert_chooser (NMA_CERT_CHOOSER (method->ca_cert_chooser), s_8021x,
	                            nm_setting_802_1x_get_ca_cert_scheme,
	                            nm_setting_802_1x_get_ca_cert_path,
	                            nm_setting_802_1x_get_ca_cert_uri,
	                            nm_setting_802_1x_get_ca_cert_password,
	                            NULL,
	                            NULL,
	                            NULL,
	                            NULL);

	if (connection && nma_eap_ca_cert_ignore_get (parent, connection)) {
		gchar *ca_cert;
		NMSetting8021xCKScheme scheme;

		ca_cert = nma_cert_chooser_get_cert (NMA_CERT_CHOOSER (method->ca_cert_chooser), &scheme);
		if (ca_cert)
			g_free (ca_cert);
		else
			ca_not_required = TRUE;
	}

	if (secrets_only)
		ca_not_required = TRUE;

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_ca_cert_not_required_checkbox"));
	g_assert (widget);
	g_object_bind_property (widget, "active",
	                        method->ca_cert_chooser, "sensitive",
	                        G_BINDING_SYNC_CREATE | G_BINDING_INVERT_BOOLEAN);
	gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), ca_not_required);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_anon_identity_entry"));
	if (s_8021x && nm_setting_802_1x_get_anonymous_identity (s_8021x))
		gtk_editable_set_text (GTK_EDITABLE (widget), nm_setting_802_1x_get_anonymous_identity (s_8021x));

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_domain_entry"));
	if (s_8021x && nm_setting_802_1x_get_domain_suffix_match (s_8021x))
		gtk_editable_set_text (GTK_EDITABLE (widget), nm_setting_802_1x_get_domain_suffix_match (s_8021x));

	widget = inner_auth_combo_init (method, connection, s_8021x, secrets_only);
	inner_auth_combo_changed_cb (widget, (gpointer) method);

	if (secrets_only) {
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_anon_identity_entry"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_domain_entry"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_ca_cert_not_required_checkbox"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_ttls_inner_auth_combo"));
		gtk_widget_hide (widget);
	}

	nma_cert_chooser_setup_cert_password_storage (NMA_CERT_CHOOSER (method->ca_cert_chooser),
	                                              0, (NMSetting *) s_8021x, NM_SETTING_802_1X_CA_CERT_PASSWORD,
	                                              FALSE, secrets_only);

	return method;
}
