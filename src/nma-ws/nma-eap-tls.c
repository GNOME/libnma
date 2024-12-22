// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 * Lubomir Rintel <lkundrak@v3.sk>
 *
 * Copyright (C) 2007 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include "nma-eap.h"
#include "nma-ws.h"
#include "nma-ws-private.h"
#include "nma-ui-utils.h"
#include "nma-cert-chooser.h"
#include "utils.h"

struct _NMAEapTls {
	NMAEap parent;

	const char *ca_cert_password_flags_name;
	const char *client_cert_password_flags_name;
	const char *client_key_password_flags_name;

	gboolean editing_connection;
	GtkWidget *ca_cert_chooser;
	GtkWidget *client_cert_chooser;
};


static gboolean
validate (NMAEap *parent, GError **error)
{
	NMAEapTls *method = (NMAEapTls *) parent;
	GtkWidget *widget;
	const char *identity;

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_tls_identity_entry"));
	g_assert (widget);
	identity = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (!identity || !*identity) {
		widget_set_error (widget);
		g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("missing EAP-TLS identity"));
		return FALSE;
	} else {
		widget_unset_error (widget);
	}

	if (   gtk_widget_get_sensitive (method->ca_cert_chooser)
	    && !nma_cert_chooser_validate (NMA_CERT_CHOOSER (method->ca_cert_chooser), error))
		return FALSE;

	if (!nma_cert_chooser_validate (NMA_CERT_CHOOSER (method->client_cert_chooser), error))
		return FALSE;

	return TRUE;
}

static void
add_to_size_group (NMAEap *parent, GtkSizeGroup *group)
{
	NMAEapTls *method = (NMAEapTls *) parent;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_tls_identity_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_tls_domain_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	nma_cert_chooser_add_to_size_group (NMA_CERT_CHOOSER (method->client_cert_chooser), group);
	nma_cert_chooser_add_to_size_group (NMA_CERT_CHOOSER (method->ca_cert_chooser), group);
}

static void
fill_connection (NMAEap *parent, NMConnection *connection)
{
	NMAEapTls *method = (NMAEapTls *) parent;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	NMSetting8021x *s_8021x;
	NMSettingSecretFlags secret_flags;
	GtkWidget *widget;
	const char *text = NULL;
	char *value = NULL;
	GError *error = NULL;
	gboolean ca_cert_error = FALSE;
	NMSetting8021xCKScheme scheme;

	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);

	if (parent->phase2)
		g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTH, "tls", NULL);
	else
		nm_setting_802_1x_add_eap_method (s_8021x, "tls");

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_tls_identity_entry"));
	g_assert (widget);
	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, gtk_editable_get_text (GTK_EDITABLE (widget)), NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_tls_domain_entry"));
	g_assert (widget);
	text = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (text && *text) {
		g_object_set (s_8021x,
		              parent->phase2 ? NM_SETTING_802_1X_PHASE2_DOMAIN_SUFFIX_MATCH : NM_SETTING_802_1X_DOMAIN_SUFFIX_MATCH,
		              gtk_editable_get_text (GTK_EDITABLE (widget)), NULL);
	}

	/* TLS private key */
	text = nma_cert_chooser_get_key_password (NMA_CERT_CHOOSER (method->client_cert_chooser));
	value = nma_cert_chooser_get_key (NMA_CERT_CHOOSER (method->client_cert_chooser), &scheme);

	if (parent->phase2) {
		if (!nm_setting_802_1x_set_phase2_private_key (s_8021x, value, text, scheme, &format, &error)) {
			g_warning ("Couldn't read phase2 private key '%s': %s", value, error ? error->message : "(unknown)");
			g_clear_error (&error);
		}
	} else {
		if (!nm_setting_802_1x_set_private_key (s_8021x, value, text, scheme, &format, &error)) {
			g_warning ("Couldn't read private key '%s': %s", value, error ? error->message : "(unknown)");
			g_clear_error (&error);
		}
	}
	g_free (value);

	/* Save CA certificate PIN and its flags to the connection */
	secret_flags = nma_cert_chooser_get_cert_password_flags (NMA_CERT_CHOOSER (method->ca_cert_chooser));
	nm_setting_set_secret_flags (NM_SETTING (s_8021x), method->ca_cert_password_flags_name,
	                             secret_flags, NULL);
	if (method->editing_connection) {
		/* Update secret flags and popup when editing the connection */
		nma_cert_chooser_update_cert_password_storage (NMA_CERT_CHOOSER (method->ca_cert_chooser),
		                                               secret_flags, NM_SETTING (s_8021x),
		                                               method->ca_cert_password_flags_name);
		g_object_set (s_8021x, method->ca_cert_password_flags_name,
		              nma_cert_chooser_get_cert_password (NMA_CERT_CHOOSER (method->ca_cert_chooser)),
		              NULL);
	}

	/* Save user certificate PIN and its flags flags to the connection */
	secret_flags = nma_cert_chooser_get_cert_password_flags (NMA_CERT_CHOOSER (method->client_cert_chooser));
	nm_setting_set_secret_flags (NM_SETTING (s_8021x), method->client_cert_password_flags_name,
	                             secret_flags, NULL);
	if (method->editing_connection) {
		nma_cert_chooser_update_cert_password_storage (NMA_CERT_CHOOSER (method->client_cert_chooser),
		                                               secret_flags, NM_SETTING (s_8021x),
		                                               method->client_cert_password_flags_name);
		g_object_set (s_8021x, method->client_cert_password_flags_name,
		              nma_cert_chooser_get_cert_password (NMA_CERT_CHOOSER (method->client_cert_chooser)),
		              NULL);
	}

	/* Save user private key password flags to the connection */
	secret_flags = nma_cert_chooser_get_key_password_flags (NMA_CERT_CHOOSER (method->client_cert_chooser));
	nm_setting_set_secret_flags (NM_SETTING (s_8021x), method->client_key_password_flags_name,
	                             secret_flags, NULL);
	if (method->editing_connection) {
		nma_cert_chooser_update_key_password_storage (NMA_CERT_CHOOSER (method->client_cert_chooser),
		                                              secret_flags, NM_SETTING (s_8021x),
		                                              method->client_key_password_flags_name);
	}

	/* TLS client certificate */
	if (format != NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
		/* If the key is pkcs#12 nm_setting_802_1x_set_private_key() already
		 * set the client certificate for us.
		 */
		value = nma_cert_chooser_get_cert (NMA_CERT_CHOOSER (method->client_cert_chooser), &scheme);
		format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
		if (parent->phase2) {
			if (!nm_setting_802_1x_set_phase2_client_cert (s_8021x, value, scheme, &format, &error)) {
				g_warning ("Couldn't read phase2 client certificate '%s': %s", value, error ? error->message : "(unknown)");
				g_clear_error (&error);
			}
		} else {
			if (!nm_setting_802_1x_set_client_cert (s_8021x, value, scheme, &format, &error)) {
				g_warning ("Couldn't read client certificate '%s': %s", value, error ? error->message : "(unknown)");
				g_clear_error (&error);
			}
		}
		g_free (value);
	}

	/* TLS CA certificate */
	if (gtk_widget_get_sensitive (method->ca_cert_chooser))
		value = nma_cert_chooser_get_cert (NMA_CERT_CHOOSER (method->ca_cert_chooser), &scheme);
	else
		value = NULL;
	format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	if (parent->phase2) {
		if (!nm_setting_802_1x_set_phase2_ca_cert (s_8021x, value, scheme, &format, &error)) {
			g_warning ("Couldn't read phase2 CA certificate '%s': %s", value, error ? error->message : "(unknown)");
			g_clear_error (&error);
			ca_cert_error = TRUE;
		}
	} else {
		if (!nm_setting_802_1x_set_ca_cert (s_8021x, value, scheme, &format, &error)) {
			g_warning ("Couldn't read CA certificate '%s': %s", value, error ? error->message : "(unknown)");
			g_clear_error (&error);
			ca_cert_error = TRUE;
		}
	}
	nma_eap_ca_cert_ignore_set (parent, connection, value, ca_cert_error);
	g_free (value);
}

static GError *
client_cert_validate_cb (NMACertChooser *cert_chooser, gpointer user_data)
{
	NMSetting8021xCKScheme scheme;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	gs_unref_object NMSetting8021x *setting = NULL;
	gs_free char *value = NULL;
	GError *local = NULL;

	setting = (NMSetting8021x *) nm_setting_802_1x_new ();

	value = nma_cert_chooser_get_cert (cert_chooser, &scheme);
	if (!value) {
		return g_error_new_literal (NMA_ERROR, NMA_ERROR_GENERIC,
		                            _("no user certificate selected"));
	}
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		if (!g_file_test (value, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
			return g_error_new_literal (NMA_ERROR, NMA_ERROR_GENERIC,
			                            _("selected user certificate file does not exist"));
		}
	}

	if (!nm_setting_802_1x_set_client_cert (setting, value, scheme, &format, &local))
		return local;

	return NULL;
}

static GError *
client_key_validate_cb (NMACertChooser *cert_chooser, gpointer user_data)
{
	NMSetting8021xCKScheme scheme;
	gs_free char *value = NULL;


	value = nma_cert_chooser_get_key (cert_chooser, &scheme);
	if (!value) {
		return g_error_new_literal (NMA_ERROR, NMA_ERROR_GENERIC,
		                            _("no key selected"));
	}
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		if (!g_file_test (value, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
			return g_error_new_literal (NMA_ERROR, NMA_ERROR_GENERIC,
			                            _("selected key file does not exist"));
		}
	}

	return NULL;
}

static GError *
client_key_password_validate_cb (NMACertChooser *cert_chooser, gpointer user_data)
{
	NMSetting8021xCKScheme scheme;
	NMSettingSecretFlags secret_flags;
	gs_unref_object NMSetting8021x *setting = NULL;
	gs_free char *value = NULL;
	const char *password = NULL;
	GError *local = NULL;

	secret_flags = nma_cert_chooser_get_key_password_flags (cert_chooser);
	if (   secret_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED
	    || secret_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		return NULL;

	setting = (NMSetting8021x *) nm_setting_802_1x_new ();

	value = nma_cert_chooser_get_key (cert_chooser, &scheme);
	password = nma_cert_chooser_get_key_password (cert_chooser);
	if (!nm_setting_802_1x_set_private_key (setting, value, password, scheme, NULL, &local))
		return local;

	return NULL;
}

static void
client_cert_fixup_pkcs12 (NMACertChooser *cert_chooser, gpointer user_data)
{
	NMSetting8021xCKScheme cert_scheme, key_scheme;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	gs_free char *cert_value = NULL;
	gs_free char *key_value = NULL;
	gs_unref_object NMSetting8021x *setting = NULL;

	setting = (NMSetting8021x *) nm_setting_802_1x_new ();

	cert_value = nma_cert_chooser_get_cert (cert_chooser, &cert_scheme);
	key_value = nma_cert_chooser_get_key (cert_chooser, &key_scheme);

	if (   !cert_value || key_value
	    || !nm_setting_802_1x_set_client_cert (setting, cert_value, cert_scheme, &format, NULL))
		return;

	if (format == NM_SETTING_802_1X_CK_FORMAT_PKCS12)
		nma_cert_chooser_set_key (cert_chooser, cert_value, cert_scheme);
}

static void
update_secrets (NMAEap *parent, NMConnection *connection)
{
	NMAEapTls *method = (NMAEapTls *) parent;

	nma_eap_setup_cert_chooser (NMA_CERT_CHOOSER (method->client_cert_chooser),
	                            nm_connection_get_setting_802_1x (connection),
	                            NULL,
	                            NULL,
	                            NULL,
	                            parent->phase2 ? nm_setting_802_1x_get_phase2_client_cert_password : nm_setting_802_1x_get_client_cert_password,
	                            parent->phase2 ? nm_setting_802_1x_get_phase2_private_key_scheme : nm_setting_802_1x_get_private_key_scheme,
	                            parent->phase2 ? nm_setting_802_1x_get_phase2_private_key_path : nm_setting_802_1x_get_private_key_path,
	                            parent->phase2 ? nm_setting_802_1x_get_phase2_private_key_uri : nm_setting_802_1x_get_private_key_uri,
	                            parent->phase2 ? nm_setting_802_1x_get_phase2_private_key_password : nm_setting_802_1x_get_private_key_password);
}

NMAEapTls *
nma_eap_tls_new (NMAWs8021x *ws_8021x,
                 NMConnection *connection,
                 gboolean phase2,
                 gboolean secrets_only)
{
	NMAEapTls *method;
	NMAEap *parent;
	GtkWidget *widget;
	NMSetting8021x *s_8021x = NULL;
	gboolean ca_not_required = FALSE;

	parent = nma_eap_init (NMA_WS (ws_8021x),
	                       sizeof (NMAEapTls),
	                       validate,
	                       add_to_size_group,
	                       fill_connection,
	                       update_secrets,
	                       NULL,
	                       "/org/gnome/libnma/nma-eap-tls.ui",
	                       "eap_tls_grid",
	                       "eap_tls_identity_entry",
	                       phase2);
	if (!parent)
		return NULL;

	method = (NMAEapTls *) parent;
	method->ca_cert_password_flags_name = phase2
	                                      ? NM_SETTING_802_1X_PHASE2_CA_CERT_PASSWORD
	                                      : NM_SETTING_802_1X_CA_CERT_PASSWORD;
	method->client_cert_password_flags_name = phase2
	                                          ? NM_SETTING_802_1X_PHASE2_CLIENT_CERT_PASSWORD
	                                          : NM_SETTING_802_1X_CLIENT_CERT_PASSWORD;
	method->client_key_password_flags_name = phase2
	                                         ? NM_SETTING_802_1X_PHASE2_PRIVATE_KEY_PASSWORD
	                                         : NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD;
	method->editing_connection = secrets_only ? FALSE : TRUE;

	if (connection)
		s_8021x = nm_connection_get_setting_802_1x (connection);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_tls_identity_entry"));
	g_assert (widget);
	if (s_8021x && nm_setting_802_1x_get_identity (s_8021x))
		gtk_editable_set_text (GTK_EDITABLE (widget), nm_setting_802_1x_get_identity (s_8021x));

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_tls_domain_entry"));
	g_assert (widget);
	if (phase2) {
		if (s_8021x && nm_setting_802_1x_get_phase2_domain_suffix_match (s_8021x))
			gtk_editable_set_text (GTK_EDITABLE (widget), nm_setting_802_1x_get_phase2_domain_suffix_match (s_8021x));
	} else {
		if (s_8021x && nm_setting_802_1x_get_domain_suffix_match (s_8021x))
			gtk_editable_set_text (GTK_EDITABLE (widget), nm_setting_802_1x_get_domain_suffix_match (s_8021x));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_tls_grid"));
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
	                            phase2 ? nm_setting_802_1x_get_phase2_ca_cert_scheme : nm_setting_802_1x_get_ca_cert_scheme,
	                            phase2 ? nm_setting_802_1x_get_phase2_ca_cert_path : nm_setting_802_1x_get_ca_cert_path,
	                            phase2 ? nm_setting_802_1x_get_phase2_ca_cert_uri : nm_setting_802_1x_get_ca_cert_uri,
	                            phase2 ? nm_setting_802_1x_get_phase2_ca_cert_password : nm_setting_802_1x_get_ca_cert_password,
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

	method->client_cert_chooser = nma_cert_chooser_new ("User",
	                                                    secrets_only ? NMA_CERT_CHOOSER_FLAG_PASSWORDS : 0);
	gtk_grid_attach (GTK_GRID (widget), method->client_cert_chooser, 0, 4, 2, 1);
	gtk_widget_show (method->client_cert_chooser);

	g_signal_connect (method->client_cert_chooser, "cert-validate",
	                  G_CALLBACK (client_cert_validate_cb),
	                  NULL);
	g_signal_connect (method->client_cert_chooser,
	                  "key-validate",
	                  G_CALLBACK (client_key_validate_cb),
	                  NULL);
	g_signal_connect (method->client_cert_chooser,
	                  "key-password-validate",
	                  G_CALLBACK (client_key_password_validate_cb),
	                  NULL);
	g_signal_connect (method->client_cert_chooser,
	                  "changed",
	                  G_CALLBACK (client_cert_fixup_pkcs12),
	                  ws_8021x);
	g_signal_connect (method->client_cert_chooser,
	                  "changed",
	                  G_CALLBACK (nma_ws_changed_cb),
	                  ws_8021x);

	nma_eap_setup_cert_chooser (NMA_CERT_CHOOSER (method->client_cert_chooser), s_8021x,
	                            phase2 ? nm_setting_802_1x_get_phase2_client_cert_scheme : nm_setting_802_1x_get_client_cert_scheme,
	                            phase2 ? nm_setting_802_1x_get_phase2_client_cert_path : nm_setting_802_1x_get_client_cert_path,
	                            phase2 ? nm_setting_802_1x_get_phase2_client_cert_uri : nm_setting_802_1x_get_client_cert_uri,
	                            phase2 ? nm_setting_802_1x_get_phase2_client_cert_password : nm_setting_802_1x_get_client_cert_password,
	                            phase2 ? nm_setting_802_1x_get_phase2_private_key_scheme : nm_setting_802_1x_get_private_key_scheme,
	                            phase2 ? nm_setting_802_1x_get_phase2_private_key_path : nm_setting_802_1x_get_private_key_path,
	                            phase2 ? nm_setting_802_1x_get_phase2_private_key_uri : nm_setting_802_1x_get_private_key_uri,
	                            phase2 ? nm_setting_802_1x_get_phase2_private_key_password : nm_setting_802_1x_get_private_key_password);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_tls_ca_cert_not_required_checkbox"));
	g_assert (widget);
	g_object_bind_property (widget, "active",
	                        method->ca_cert_chooser, "sensitive",
	                        G_BINDING_SYNC_CREATE | G_BINDING_INVERT_BOOLEAN);
	gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), ca_not_required);

	/* Create password-storage popup menus for password entries under their secondary icon */
	nma_cert_chooser_setup_cert_password_storage (NMA_CERT_CHOOSER (method->ca_cert_chooser),
	                                              0, (NMSetting *) s_8021x, method->ca_cert_password_flags_name,
	                                              FALSE, secrets_only);
	nma_cert_chooser_setup_cert_password_storage (NMA_CERT_CHOOSER (method->client_cert_chooser),
	                                              0, (NMSetting *) s_8021x, method->client_cert_password_flags_name,
	                                              FALSE, secrets_only);
	nma_cert_chooser_setup_key_password_storage (NMA_CERT_CHOOSER (method->client_cert_chooser),
	                                             0, (NMSetting *) s_8021x, method->client_key_password_flags_name,
	                                             FALSE, secrets_only);

	return method;
}
