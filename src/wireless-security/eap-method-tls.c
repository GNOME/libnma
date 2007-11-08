/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2007 Red Hat, Inc.
 */

#include <glade/glade.h>
#include <glib/gi18n.h>
#include <ctype.h>
#include <string.h>
#include <nm-setting-wireless.h>

#include "gconf-helpers.h"
#include "eap-method.h"
#include "wireless-security.h"

static void
show_toggled_cb (GtkCheckButton *button, EAPMethod *method)
{
	GtkWidget *widget;
	gboolean visible;

	widget = glade_xml_get_widget (method->xml, "eap_tls_private_key_password_entry");
	g_assert (widget);

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
}

static void
destroy (EAPMethod *parent)
{
	EAPMethodTLS *method = (EAPMethodTLS *) parent;

	g_object_unref (method->nag_dialog_xml);
	g_object_unref (parent->xml);
	g_slice_free (EAPMethodTLS, method);
}

static gboolean
validate (EAPMethod *parent)
{
	GtkWidget *widget;
	const char *text;

	widget = glade_xml_get_widget (parent->xml, "eap_tls_identity_entry");
	g_assert (widget);
	text = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!text || !strlen (text))
		return FALSE;

	if (!eap_method_validate_filepicker (parent->xml, "eap_tls_user_cert_button", FALSE, FALSE, NULL))
		return FALSE;

	if (!eap_method_validate_filepicker (parent->xml, "eap_tls_ca_cert_button", TRUE, FALSE, NULL))
		return FALSE;

	if (!eap_method_validate_filepicker (parent->xml,
	                                     "eap_tls_private_key_button",
	                                     FALSE,
	                                     TRUE,
	                                     "eap_tls_private_key_password_entry"))
		return FALSE;

	widget = glade_xml_get_widget (parent->xml, "eap_tls_private_key_password_entry");
	g_assert (widget);
	// FIXME: require encrypted private keys for now
	text = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!text || !strlen (text))
		return FALSE;

	return TRUE;
}

static void
add_to_size_group (EAPMethod *parent, GtkSizeGroup *group)
{
	GtkWidget *widget;

	widget = glade_xml_get_widget (parent->xml, "eap_tls_identity_label");
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = glade_xml_get_widget (parent->xml, "eap_tls_user_cert_label");
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = glade_xml_get_widget (parent->xml, "eap_tls_ca_cert_label");
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = glade_xml_get_widget (parent->xml, "eap_tls_private_key_label");
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = glade_xml_get_widget (parent->xml, "eap_tls_private_key_password_label");
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);
}

static void
fill_connection (EAPMethod *parent, NMConnection *connection)
{
	EAPMethodTLS *method = (EAPMethodTLS *) parent;
	NMSettingWirelessSecurity *s_wireless_sec;
	GtkWidget *widget;
	char *filename;

	s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, 
										  NM_TYPE_SETTING_WIRELESS_SECURITY));
	g_assert (s_wireless_sec);

	if (method->phase2)
		s_wireless_sec->phase2_auth = g_strdup ("tls");
	else
		s_wireless_sec->eap = g_slist_append (s_wireless_sec->eap, g_strdup ("tls"));

	// FIXME: allow protocol selection and filter on device capabilities
	// FIXME: allow pairwise cipher selection and filter on device capabilities
	// FIXME: allow group cipher selection and filter on device capabilities
	ws_wpa_fill_default_ciphers (connection);

	widget = glade_xml_get_widget (parent->xml, "eap_tls_identity_entry");
	g_assert (widget);
	s_wireless_sec->identity = g_strdup (gtk_entry_get_text (GTK_ENTRY (widget)));

	widget = glade_xml_get_widget (parent->xml, "eap_tls_user_cert_button");
	g_assert (widget);
	filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	g_object_set_data_full (G_OBJECT (connection),
	                        method->phase2 ? NMA_PATH_PHASE2_CLIENT_CERT_TAG : NMA_PATH_CLIENT_CERT_TAG,
	                        g_strdup (filename),
	                        (GDestroyNotify) g_free);

	widget = glade_xml_get_widget (parent->xml, "eap_tls_ca_cert_button");
	g_assert (widget);
	filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (filename) {
		g_object_set_data_full (G_OBJECT (connection),
		                        method->phase2 ? NMA_PATH_PHASE2_CA_CERT_TAG : NMA_PATH_CA_CERT_TAG,
		                        g_strdup (filename),
		                        (GDestroyNotify) g_free);
	} else {
		g_object_set_data (G_OBJECT (connection),
		                   method->phase2 ? NMA_PATH_PHASE2_CA_CERT_TAG : NMA_PATH_CA_CERT_TAG,
		                   NULL);
	}

	widget = glade_xml_get_widget (parent->xml, "eap_tls_private_key_button");
	g_assert (widget);
	filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	g_object_set_data_full (G_OBJECT (connection),
	                        method->phase2 ? NMA_PATH_PHASE2_PRIVATE_KEY_TAG : NMA_PATH_PRIVATE_KEY_TAG,
	                        g_strdup (filename),
	                        (GDestroyNotify) g_free);

	widget = glade_xml_get_widget (parent->xml, "eap_tls_private_key_password_entry");
	g_assert (widget);
	if (method->phase2)
		s_wireless_sec->phase2_private_key_passwd = g_strdup (gtk_entry_get_text (GTK_ENTRY (widget)));
	else
		s_wireless_sec->private_key_passwd = g_strdup (gtk_entry_get_text (GTK_ENTRY (widget)));

	if (method->ignore_ca_cert) {
		g_object_set_data (G_OBJECT (connection),
		                   method->phase2 ? NMA_PHASE2_CA_CERT_IGNORE_TAG : NMA_CA_CERT_IGNORE_TAG,
		                   GUINT_TO_POINTER (TRUE));
	} else {
		g_object_set_data (G_OBJECT (connection),
		                   method->phase2 ? NMA_PHASE2_CA_CERT_IGNORE_TAG : NMA_CA_CERT_IGNORE_TAG,
		                   NULL);
	}
}

static gboolean
nag_dialog_destroy (gpointer user_data)
{
	GtkWidget *nag_dialog = GTK_WIDGET (user_data);

	gtk_widget_destroy (nag_dialog);
	return FALSE;
}

static void
nag_dialog_response_cb (GtkDialog *nag_dialog,
                        gint response,
                        gpointer user_data)
{
	EAPMethodTLS *method = (EAPMethodTLS *) user_data;
	GtkWidget *widget;

	if (response != GTK_RESPONSE_NO)
		goto out;

	/* Grab the value of the "don't bother me" checkbox */
	widget = glade_xml_get_widget (method->nag_dialog_xml, "ignore_checkbox");
	g_assert (widget);

	method->ignore_ca_cert = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget));

out:
	gtk_widget_hide (GTK_WIDGET (nag_dialog));
	g_idle_add (nag_dialog_destroy, nag_dialog);
}

static GtkWidget *
nag_user (EAPMethod *parent)
{
	GtkWidget *dialog;
	GtkWidget *widget;
	EAPMethodTLS *method = (EAPMethodTLS *) parent;
	char *filename = NULL;
	char *text;

	if (method->ignore_ca_cert)
		return NULL;

	/* Nag the user if the CA Cert is blank, since it's a security risk. */
	widget = glade_xml_get_widget (parent->xml, "eap_tls_ca_cert_button");
	g_assert (widget);
	filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (filename != NULL) {
		g_free (filename);
		return NULL;
	}

	dialog = glade_xml_get_widget (method->nag_dialog_xml, "nag_user_dialog");
	g_assert (dialog);
	g_signal_connect (dialog, "response", G_CALLBACK (nag_dialog_response_cb), method);
	
	widget = glade_xml_get_widget (method->nag_dialog_xml, "content_label");
	g_assert (widget);

	text = g_strdup_printf ("<span weight=\"bold\" size=\"larger\">%s</span>\n\n%s",
	                        _("No Certificate Authority certificate chosen"),
	                        _("Not using a Certificate Authority (CA) certificate can result in connections to insecure, rogue wireless networks.  Would you like to choose a Certificate Authority certificate?"));
	gtk_label_set_markup (GTK_LABEL (widget), text);
	g_free (text);

	widget = glade_xml_get_widget (method->nag_dialog_xml, "ignore_button");
	gtk_button_set_label (GTK_BUTTON (widget), _("Ignore"));
	g_assert (widget);

	widget = glade_xml_get_widget (method->nag_dialog_xml, "change_button");
	gtk_button_set_label (GTK_BUTTON (widget), _("Choose CA Certificate"));
	g_assert (widget);

	gtk_widget_realize (dialog);
	gtk_window_present (GTK_WINDOW (dialog));
	return dialog;
}

static void
setup_filepicker (GladeXML *xml,
                  const char *name,
                  const char *title,
                  WirelessSecurity *parent)
{
	GtkWidget *widget;
	GtkFileFilter *filter;

	widget = glade_xml_get_widget (xml, name);
	g_assert (widget);
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget), title);
	g_signal_connect (G_OBJECT (widget), "selection-changed",
	                  (GCallback) wireless_security_changed_cb,
	                  parent);

	filter = eap_method_default_file_chooser_filter_new ();
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
}

EAPMethodTLS *
eap_method_tls_new (const char *glade_file,
                    WirelessSecurity *parent,
                    NMConnection *connection,
                    gboolean phase2)
{
	EAPMethodTLS *method;
	GtkWidget *widget;
	GladeXML *xml;
	GladeXML *nag_dialog_xml;

	g_return_val_if_fail (glade_file != NULL, NULL);

	xml = glade_xml_new (glade_file, "eap_tls_notebook", NULL);
	if (xml == NULL) {
		g_warning ("Couldn't get eap_tls_widget from glade xml");
		return NULL;
	}

	nag_dialog_xml = glade_xml_new (glade_file, "nag_user_dialog", NULL);
	if (nag_dialog_xml == NULL) {
		g_warning ("Couldn't get nag_user_dialog from glade xml");
		g_object_unref (xml);
		return NULL;
	}

	widget = glade_xml_get_widget (xml, "eap_tls_notebook");
	g_assert (widget);

	method = g_slice_new0 (EAPMethodTLS);
	if (!method) {
		g_object_unref (xml);
		g_object_unref (nag_dialog_xml);
		return NULL;
	}

	eap_method_init (EAP_METHOD (method),
	                 validate,
	                 add_to_size_group,
	                 fill_connection,
	                 destroy,
	                 xml,
	                 g_object_ref (widget));

	EAP_METHOD (method)->nag_user = nag_user;
	method->nag_dialog_xml = nag_dialog_xml;

	method->phase2 = phase2;

	if (connection)
		method->ignore_ca_cert = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), NMA_CA_CERT_IGNORE_TAG));

	widget = glade_xml_get_widget (xml, "eap_tls_identity_entry");
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "changed",
	                  (GCallback) wireless_security_changed_cb,
	                  parent);

	widget = glade_xml_get_widget (xml, "eap_tls_private_key_password_entry");
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "changed",
	                  (GCallback) wireless_security_changed_cb,
	                  parent);

	setup_filepicker (xml,
	                  "eap_tls_user_cert_button",
	                  _("Choose your personal certificate..."),
	                  parent);
	setup_filepicker (xml,
	                  "eap_tls_ca_cert_button",
	                  _("Choose a Certificate Authority certificate..."),
	                  parent);
	setup_filepicker (xml,
	                  "eap_tls_private_key_button",
	                  _("Choose your private key..."),
	                  parent);

	widget = glade_xml_get_widget (xml, "show_checkbutton");
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "toggled",
	                  (GCallback) show_toggled_cb,
	                  method);

	return method;
}

