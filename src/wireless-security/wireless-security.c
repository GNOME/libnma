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

#include <string.h>

#include <glib.h>
#include <gtk/gtk.h>
#include <glib/gi18n.h>

#include <nm-setting-wireless.h>

#include "wireless-security.h"
#include "eap-method.h"

GType
wireless_security_get_g_type (void)
{
	static GType type_id = 0;

	if (!type_id) {
		type_id = g_boxed_type_register_static ("WirelessSecurity",
		                                        (GBoxedCopyFunc) wireless_security_ref,
		                                        (GBoxedFreeFunc) wireless_security_unref);
	}

	return type_id;
}

GtkWidget *
wireless_security_get_widget (WirelessSecurity *sec)
{
	g_return_val_if_fail (sec != NULL, NULL);

	return sec->ui_widget;
}

void
wireless_security_set_changed_notify (WirelessSecurity *sec,
                                      WSChangedFunc func,
                                      gpointer user_data)
{
	g_return_if_fail (sec != NULL);

	sec->changed_notify = func;
	sec->changed_notify_data = user_data;
}

void
wireless_security_changed_cb (GtkWidget *ignored, gpointer user_data)
{
	WirelessSecurity *sec = WIRELESS_SECURITY (user_data);

	if (sec->changed_notify)
		(*(sec->changed_notify)) (sec, sec->changed_notify_data);
}

gboolean
wireless_security_validate (WirelessSecurity *sec, const GByteArray *ssid)
{
	g_return_val_if_fail (sec != NULL, FALSE);

	g_assert (sec->validate);
	return (*(sec->validate)) (sec, ssid);
}

void
wireless_security_add_to_size_group (WirelessSecurity *sec, GtkSizeGroup *group)
{
	g_return_if_fail (sec != NULL);
	g_return_if_fail (group != NULL);

	g_assert (sec->add_to_size_group);
	return (*(sec->add_to_size_group)) (sec, group);
}

void
wireless_security_fill_connection (WirelessSecurity *sec,
                                   NMConnection *connection)
{
	g_return_if_fail (sec != NULL);
	g_return_if_fail (connection != NULL);

	g_assert (sec->fill_connection);
	return (*(sec->fill_connection)) (sec, connection);
}

WirelessSecurity *
wireless_security_ref (WirelessSecurity *sec)
{
	g_return_val_if_fail (sec != NULL, NULL);
	g_return_val_if_fail (sec->refcount > 0, NULL);

	sec->refcount++;
	return sec;
}

void
wireless_security_unref (WirelessSecurity *sec)
{
	g_return_if_fail (sec != NULL);
	g_return_if_fail (sec->refcount > 0);

	g_assert (sec->destroy);

	sec->refcount--;
	if (sec->refcount == 0)
		(*(sec->destroy)) (sec);
}

void
ws_wep_fill_connection (NMConnection *connection,
                        const char *key,
                        int auth_alg)
{
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	g_assert (s_wireless);

	if (s_wireless->security)
		g_free (s_wireless->security);
	s_wireless->security = g_strdup (NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	/* Blow away the old security setting by adding a clear one */
	s_wireless_sec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, (NMSetting *) s_wireless_sec);

	s_wireless_sec->wep_key0 = g_strdup (key);
	s_wireless_sec->key_mgmt = g_strdup ("none");
	s_wireless_sec->wep_tx_keyidx = 0;

	switch (auth_alg) {
		case 0:
			s_wireless_sec->auth_alg = g_strdup ("open");
			break;
		case 1:
			s_wireless_sec->auth_alg = g_strdup ("shared");
			break;
		default:
			g_assert_not_reached ();
			break;
	}
}

void
wireless_security_init (WirelessSecurity *sec,
                        WSValidateFunc validate,
                        WSAddToSizeGroupFunc add_to_size_group,
                        WSFillConnectionFunc fill_connection,
                        WSDestroyFunc destroy,
                        GladeXML *xml,
                        GtkWidget *ui_widget)
{
	sec->refcount = 1;

	sec->validate = validate;
	sec->add_to_size_group = add_to_size_group;
	sec->fill_connection = fill_connection;
	sec->destroy = destroy;

	sec->xml = xml;
	sec->ui_widget = ui_widget;
}

void
ws_wpa_fill_default_ciphers (NMConnection *connection)
{
	NMSettingWirelessSecurity *s_wireless_sec;

	g_return_if_fail (connection != NULL);

	s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection,
										  NM_TYPE_SETTING_WIRELESS_SECURITY));
	g_assert (s_wireless_sec);

	// FIXME: allow protocol selection and filter on device capabilities
	s_wireless_sec->proto = g_slist_append (s_wireless_sec->proto, g_strdup ("wpa"));
	s_wireless_sec->proto = g_slist_append (s_wireless_sec->proto, g_strdup ("rsn"));

	// FIXME: allow pairwise cipher selection and filter on device capabilities
	s_wireless_sec->pairwise = g_slist_append (s_wireless_sec->pairwise, g_strdup ("tkip"));
	s_wireless_sec->pairwise = g_slist_append (s_wireless_sec->pairwise, g_strdup ("ccmp"));

	// FIXME: allow group cipher selection and filter on device capabilities
	s_wireless_sec->group = g_slist_append (s_wireless_sec->group, g_strdup ("wep40"));
	s_wireless_sec->group = g_slist_append (s_wireless_sec->group, g_strdup ("wep104"));
	s_wireless_sec->group = g_slist_append (s_wireless_sec->group, g_strdup ("tkip"));
	s_wireless_sec->group = g_slist_append (s_wireless_sec->group, g_strdup ("ccmp"));
}

void
ws_802_1x_add_to_size_group (WirelessSecurity *sec,
                             GtkSizeGroup *size_group,
                             const char *label_name,
                             const char *combo_name)
{
	GtkWidget *widget;
	GtkTreeModel *model;
	GtkTreeIter iter;
	EAPMethod *eap;

	widget = glade_xml_get_widget (sec->xml, label_name);
	g_assert (widget);
	gtk_size_group_add_widget (size_group, widget);

	widget = glade_xml_get_widget (sec->xml, combo_name);
	g_assert (widget);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	gtk_tree_model_get (model, &iter, AUTH_METHOD_COLUMN, &eap, -1);
	g_assert (eap);
	eap_method_add_to_size_group (eap, size_group);
	eap_method_unref (eap);
}

gboolean
ws_802_1x_validate (WirelessSecurity *sec, const char *combo_name)
{
	GtkWidget *widget;
	GtkTreeModel *model;
	GtkTreeIter iter;
	EAPMethod *eap = NULL;
	gboolean valid = FALSE;

	widget = glade_xml_get_widget (sec->xml, combo_name);
	g_assert (widget);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	gtk_tree_model_get (model, &iter, AUTH_METHOD_COLUMN, &eap, -1);
	g_assert (eap);
	valid = eap_method_validate (eap);
	eap_method_unref (eap);
	return valid;
}

void
ws_802_1x_auth_combo_changed (GtkWidget *combo,
                              WirelessSecurity *sec,
                              const char *vbox_name,
                              GtkSizeGroup *size_group)
{
	GtkWidget *vbox;
	EAPMethod *eap = NULL;
	GList *elt, *children;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkWidget *eap_widget;

	vbox = glade_xml_get_widget (sec->xml, vbox_name);
	g_assert (vbox);

	/* Remove any previous wireless security widgets */
	children = gtk_container_get_children (GTK_CONTAINER (vbox));
	for (elt = children; elt; elt = g_list_next (elt))
		gtk_container_remove (GTK_CONTAINER (vbox), GTK_WIDGET (elt->data));

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter);
	gtk_tree_model_get (model, &iter, AUTH_METHOD_COLUMN, &eap, -1);
	g_assert (eap);

	eap_widget = eap_method_get_widget (eap);
	g_assert (eap_widget);

	if (size_group)
		eap_method_add_to_size_group (eap, size_group);
	gtk_container_add (GTK_CONTAINER (vbox), eap_widget);

	eap_method_unref (eap);

	wireless_security_changed_cb (combo, WIRELESS_SECURITY (sec));
}

GtkWidget *
ws_802_1x_auth_combo_init (WirelessSecurity *sec,
                           const char *glade_file,
                           const char *combo_name,
                           GCallback auth_combo_changed_cb,
                           const char *default_method)
{
	GtkWidget *combo;
	GtkListStore *auth_model;
	GtkTreeIter iter;
	EAPMethodTLS *em_tls;
	EAPMethodLEAP *em_leap;
	EAPMethodTTLS *em_ttls;
	int active = -1;

	auth_model = gtk_list_store_new (2, G_TYPE_STRING, eap_method_get_g_type ());

	em_tls = eap_method_tls_new (glade_file, sec);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    AUTH_NAME_COLUMN, _("TLS"),
	                    AUTH_METHOD_COLUMN, em_tls,
	                    -1);
	eap_method_unref (EAP_METHOD (em_tls));
	if (default_method && (active < 0) && !strcmp (default_method, "tls"))
		active = 0;

	em_leap = eap_method_leap_new (glade_file, sec);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    AUTH_NAME_COLUMN, _("LEAP"),
	                    AUTH_METHOD_COLUMN, em_leap,
	                    -1);
	eap_method_unref (EAP_METHOD (em_leap));
	if (default_method && (active < 0) && !strcmp (default_method, "leap"))
		active = 1;

	em_ttls = eap_method_ttls_new (glade_file, sec);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    AUTH_NAME_COLUMN, _("Tunneled TLS"),
	                    AUTH_METHOD_COLUMN, em_ttls,
	                    -1);
	eap_method_unref (EAP_METHOD (em_ttls));
	if (default_method && (active < 0) && !strcmp (default_method, "ttls"))
		active = 2;

	combo = glade_xml_get_widget (sec->xml, combo_name);
	g_assert (combo);

	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (auth_model));
	g_object_unref (G_OBJECT (auth_model));
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), active < 0 ? 0 : (guint32) active);

	g_signal_connect (G_OBJECT (combo), "changed", auth_combo_changed_cb, sec);

	return combo;
}

void
ws_802_1x_fill_connection (WirelessSecurity *sec,
                           const char *combo_name,
                           NMConnection *connection)
{
	GtkWidget *widget;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;
	EAPMethod *eap = NULL;
	GtkTreeModel *model;
	GtkTreeIter iter;

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	g_assert (s_wireless);

	if (s_wireless->security)
		g_free (s_wireless->security);
	s_wireless->security = g_strdup (NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);

	/* Blow away the old security setting by adding a clear one */
	s_wireless_sec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, (NMSetting *) s_wireless_sec);

	widget = glade_xml_get_widget (sec->xml, combo_name);
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	gtk_tree_model_get (model, &iter, AUTH_METHOD_COLUMN, &eap, -1);
	g_assert (eap);

	eap_method_fill_connection (eap, connection);
	eap_method_unref (eap);
}

