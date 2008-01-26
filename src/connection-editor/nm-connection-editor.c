/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
/* NetworkManager Connection editor -- Connection editor for NetworkManager
 *
 * Rodrigo Moya <rodrigo@gnome-db.org>
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
 * (C) Copyright 2004-2005 Red Hat, Inc.
 */

#include <string.h>
#include <math.h>

#include <gtk/gtkcombobox.h>
#include <gtk/gtkdialog.h>
#include <gtk/gtkentry.h>
#include <gtk/gtkspinbutton.h>
#include <gtk/gtktogglebutton.h>
#include <gtk/gtknotebook.h>
#include <gtk/gtklabel.h>
#include <glib/gi18n.h>

#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-wireless-security.h>
#include <nm-setting-vpn.h>
#include <nm-utils.h>

#include "nm-connection-editor.h"
#include "utils.h"
#include "wireless-security.h"

#define S_NAME_COLUMN		0
#define S_SEC_COLUMN		1

G_DEFINE_TYPE (NMConnectionEditor, nm_connection_editor, G_TYPE_OBJECT)

static void
dialog_response_cb (GtkDialog *dialog, guint response, gpointer user_data)
{
	gtk_widget_hide (GTK_WIDGET (dialog));
}

static int
get_property_default (NMSetting *setting, const char *property_name)
{
	GParamSpec *spec;
	GValue value = { 0, };

	spec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), property_name);
	g_return_val_if_fail (spec != NULL, -1);

	g_value_init (&value, spec->value_type);
	g_param_value_set_default (spec, &value);

	if (G_VALUE_HOLDS_CHAR (&value))
		return (int) g_value_get_char (&value);
	else if (G_VALUE_HOLDS_INT (&value))
		return g_value_get_int (&value);
	else if (G_VALUE_HOLDS_INT64 (&value))
		return (int) g_value_get_int64 (&value);
	else if (G_VALUE_HOLDS_LONG (&value))
		return (int) g_value_get_long (&value);
	else if (G_VALUE_HOLDS_UINT (&value))
		return (int) g_value_get_uint (&value);
	else if (G_VALUE_HOLDS_UINT64 (&value))
		return (int) g_value_get_uint64 (&value);
	else if (G_VALUE_HOLDS_ULONG (&value))
		return (int) g_value_get_ulong (&value);
	else if (G_VALUE_HOLDS_UCHAR (&value))
		return (int) g_value_get_uchar (&value);
	g_return_val_if_fail (FALSE, 0);
	return 0;
}

#define WIRED_PAGE "WiredPage"
#define WIRED_PREFIX "wired_"

#define WIRELESS_PAGE "WirelessPage"
#define WIRELESS_PREFIX "wireless_"

#define WIRELESS_SECURITY_PAGE "WirelessSecurityPage"
#define WIRELESS_SECURITY_PREFIX "wireless_security_"

#define IP4_PAGE "IP4Page"
#define IP4_PREFIX "ip4_"

#define IP4_ADDRESS_PAGE "IP4AddressPage"
#define IP4_ADDRESS_PREFIX "ip4_address_"

static inline gboolean
match_domain (const char *prefix, const char *page, const char *name)
{
	if (!strncmp (name, prefix, strlen (prefix)))
		return TRUE;
	if (!strcmp (name, page))
		return TRUE;
	return FALSE;
}

static inline GtkWidget *
get_widget (NMConnectionEditor *editor, const char *name)
{
	GtkWidget *widget;
	GladeXML *xml;
	char *domain = "NMConnectionEditor";

	g_return_val_if_fail (editor != NULL, NULL);

	/* This is all to ensure that the glade_xml_new() never uses the
	 * NULL domain, and therefore loads & caches the NMConnectionList
	 * widget, because if that happens when the GladeXML is destroyed
	 * the cached NMConnectionList widget is destroyed prematurely.
	 */

	if (match_domain (WIRED_PREFIX, WIRED_PAGE, name))
		domain = WIRED_PAGE;
	else if (match_domain (WIRELESS_SECURITY_PREFIX, WIRELESS_SECURITY_PAGE, name))
		domain = WIRELESS_SECURITY_PAGE;
	else if (match_domain (WIRELESS_PREFIX, WIRELESS_PAGE, name))
		domain = WIRELESS_PAGE;
	else if (match_domain (IP4_PREFIX, IP4_PAGE, name))
		domain = IP4_PAGE;
	else if (match_domain (IP4_ADDRESS_PREFIX, IP4_ADDRESS_PAGE, name))
		domain = IP4_ADDRESS_PAGE;

	xml = g_hash_table_lookup (editor->pages, domain);
	if (!xml) {
		xml = glade_xml_new (GLADEDIR "/nm-connection-editor.glade", domain, NULL);
		g_assert (xml);
		g_hash_table_insert (editor->pages, g_strdup (domain), xml);
	}

	widget = glade_xml_get_widget (xml, name);
	g_return_val_if_fail (widget != NULL, NULL);
	return widget;
}

static void
add_page (NMConnectionEditor *editor,
          const char *page_name,
          const char *label_text)
{
	GtkWidget *notebook;
	GtkWidget *page;
	GtkWidget *label;

	notebook = get_widget (editor, "notebook");
	page = get_widget (editor, page_name);
	g_object_ref (G_OBJECT (page));
	gtk_widget_unparent (page);
	label = gtk_label_new (label_text);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), page, label);
	g_object_unref (G_OBJECT (page));
}

static void
nm_connection_editor_update_title (NMConnectionEditor *editor)
{
	NMSettingConnection *s_con;

	g_return_if_fail (editor != NULL);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (s_con->id) {
		char *title = g_strdup_printf (_("Editing %s"), s_con->id);
		gtk_window_set_title (GTK_WINDOW (editor->dialog), title);
		g_free (title);
	} else
		gtk_window_set_title (GTK_WINDOW (editor->dialog), _("Editing unamed connection"));
}

static void
connection_name_changed (GtkEditable *editable, gpointer user_data)
{
	NMSettingConnection *s_con;
	NMConnectionEditor *editor = NM_CONNECTION_EDITOR (user_data);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_CONNECTION));
	if (s_con)
		g_object_set (G_OBJECT (s_con), NM_SETTING_CONNECTION_ID, gtk_entry_get_text (GTK_ENTRY (editable)), NULL);
	nm_connection_editor_update_title (editor);
}

#if 0
static void
connection_autoconnect_changed (GtkToggleButton *button, gpointer user_data)
{
	NMSettingConnection *s_connection;
	NMConnectionEditor *editor = (NMConnectionEditor *) user_data;

	s_connection = NM_SETTING_CONNECTION (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_CONNECTION));
	if (s_connection)
		s_connection->autoconnect = gtk_toggle_button_get_active (button);
}

static void
ethernet_port_changed (GtkComboBox *combo, gpointer user_data)
{
	NMSettingWired *s_wired;
	NMConnectionEditor *editor = (NMConnectionEditor *) user_data;

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_WIRED));
	if (s_wired) {
		if (s_wired->port)
			g_free (s_wired->port);

		switch (gtk_combo_box_get_active (combo)) {
		case 0 : s_wired->port = g_strdup ("tp"); break;
		case 1 : s_wired->port = g_strdup ("aui"); break;
		case 2 : s_wired->port = g_strdup ("bnc"); break;
		case 3 : s_wired->port = g_strdup ("mii"); break;
		}
	}
}

static void
ethernet_speed_changed (GtkSpinButton *button, gpointer user_data)
{
	NMSettingWired *s_wired;
	NMConnectionEditor *editor = (NMConnectionEditor *) user_data;

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_WIRED));
	if (s_wired)
		s_wired->speed = gtk_spin_button_get_value_as_int (button);
}

static void
ethernet_duplex_changed (GtkToggleButton *button, gpointer user_data)
{
	NMSettingWired *s_wired;
	NMConnectionEditor *editor = (NMConnectionEditor *) user_data;

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_WIRED));
	if (s_wired) {
		if (s_wired->duplex)
			g_free (s_wired->duplex);

		if (gtk_toggle_button_get_active (button))
			s_wired->duplex = g_strdup ("full");
		else
			s_wired->duplex = g_strdup ("half");
	}
}

static void
ethernet_autonegotiate_changed (GtkToggleButton *button, gpointer user_data)
{
	NMSettingWired *s_wired;
	NMConnectionEditor *editor = (NMConnectionEditor *) user_data;

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_WIRED));
	if (s_wired)
		s_wired->auto_negotiate = gtk_toggle_button_get_active (button);
}

static void
ethernet_mtu_changed (GtkSpinButton *button, gpointer user_data)
{
	NMSettingWired *s_wired;
	NMConnectionEditor *editor = (NMConnectionEditor *) user_data;

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_WIRED));
	if (s_wired)
		s_wired->mtu = gtk_spin_button_get_value_as_int (button);
}

static void
wireless_mode_changed (GtkComboBox *combo, gpointer user_data)
{
	NMSettingWireless *s_wireless;
	NMConnectionEditor *editor = (NMConnectionEditor *) user_data;

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_WIRELESS));
	if (s_wireless) {
		if (s_wireless->mode)
			g_free (s_wireless->mode);

		switch (gtk_combo_box_get_active (combo)) {
		case 0 : s_wireless->mode = g_strdup ("infrastructure"); break;
		case 1 : s_wireless->mode = g_strdup ("adhoc"); break;
		}
	}
}

static void
wireless_band_changed (GtkComboBox *combo, gpointer user_data)
{
	NMSettingWireless *s_wireless;
	NMConnectionEditor *editor = (NMConnectionEditor *) user_data;

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_WIRELESS));
	if (s_wireless) {
		if (s_wireless->band)
			g_free (s_wireless->band);

		switch (gtk_combo_box_get_active (combo)) {
		case 0 : s_wireless->band = g_strdup ("a"); break;
		case 1 : s_wireless->band = g_strdup ("bg"); break;
		}
	}
}

static void
wireless_channel_changed (GtkSpinButton *button, gpointer user_data)
{
	NMSettingWireless *s_wireless;
	NMConnectionEditor *editor = (NMConnectionEditor *) user_data;

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_WIRELESS));
	if (s_wireless)
		s_wireless->channel = gtk_spin_button_get_value_as_int (button);
}

static void
wireless_rate_changed (GtkSpinButton *button, gpointer user_data)
{
	NMSettingWireless *s_wireless;
	NMConnectionEditor *editor = (NMConnectionEditor *) user_data;

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_WIRELESS));
	if (s_wireless)
		s_wireless->rate = gtk_spin_button_get_value_as_int (button);
}

static void
wireless_tx_power_changed (GtkSpinButton *button, gpointer user_data)
{
	NMSettingWireless *s_wireless;
	NMConnectionEditor *editor = (NMConnectionEditor *) user_data;

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_WIRELESS));
	if (s_wireless)
		s_wireless->tx_power = gtk_spin_button_get_value_as_int (button);
}

static void
wireless_mtu_changed (GtkSpinButton *button, gpointer user_data)
{
	NMSettingWireless *s_wireless;
	NMConnectionEditor *editor = (NMConnectionEditor *) user_data;

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_WIRELESS));
	if (s_wireless)
		s_wireless->mtu = gtk_spin_button_get_value_as_int (button);
}
#endif

static void
nm_connection_editor_init (NMConnectionEditor *editor)
{
	GtkWidget *widget;

	if (!g_file_test (GLADEDIR "/applet.glade", G_FILE_TEST_EXISTS)) {
		GtkWidget *dialog;

		dialog = gtk_message_dialog_new (NULL, 0,
		                                 GTK_MESSAGE_ERROR,
		                                 GTK_BUTTONS_OK,
		                                 "%s",
		                                 _("The connection editor could not find some required resources (the NetworkManager applet glade file was not found)."));
		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
		gtk_main_quit ();
		return;
	}

	editor->pages = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);

	editor->dialog = get_widget (editor, "NMConnectionEditor");
	g_signal_connect (G_OBJECT (editor->dialog), "response", G_CALLBACK (dialog_response_cb), editor);

	widget = get_widget (editor, "connection_name");
	g_signal_connect (G_OBJECT (widget), "changed",
	                  G_CALLBACK (connection_name_changed), editor);

	editor->wsec_group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);
}

static void
nm_connection_editor_finalize (GObject *object)
{
	NMConnectionEditor *editor = NM_CONNECTION_EDITOR (object);

	if (editor->connection)
		g_object_unref (G_OBJECT (editor->connection));

	gtk_widget_destroy (editor->dialog);
	g_object_unref (G_OBJECT (editor->wsec_group));
	g_hash_table_destroy (editor->pages);

	G_OBJECT_CLASS (nm_connection_editor_parent_class)->finalize (object);
}

static void
nm_connection_editor_class_init (NMConnectionEditorClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	/* virtual methods */
	object_class->finalize = nm_connection_editor_finalize;
}

NMConnectionEditor *
nm_connection_editor_new (NMConnection *connection)
{
	NMConnectionEditor *editor;

	g_return_val_if_fail (connection != NULL, NULL);

	editor = g_object_new (NM_TYPE_CONNECTION_EDITOR, NULL);
	nm_connection_editor_set_connection (editor, connection);

	return editor;
}

NMConnection *
nm_connection_editor_get_connection (NMConnectionEditor *editor)
{
	g_return_val_if_fail (NM_IS_CONNECTION_EDITOR (editor), NULL);

	return editor->connection;
}

static void
fill_connection_values (NMConnectionEditor *editor)
{
	NMSettingConnection *s_con;
	GtkWidget *name;
	GtkWidget *autoconnect;

	name = get_widget (editor, "connection_name");
	autoconnect = get_widget (editor, "connection_autoconnect");

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_CONNECTION));
	if (s_con) {
		gtk_entry_set_text (GTK_ENTRY (name), s_con->id);
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (autoconnect), s_con->autoconnect);
	} else {
		gtk_entry_set_text (GTK_ENTRY (name), NULL);
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (autoconnect), FALSE);
	}
}

static gint
spin_output_with_default (GtkSpinButton *spin, gpointer user_data)
{
	int defvalue = GPOINTER_TO_INT (user_data);
	int val;
	gchar *buf = NULL;

	val = gtk_spin_button_get_value_as_int (spin);
	if (val == defvalue)
		buf = g_strdup (_("default"));
	else
		buf = g_strdup_printf ("%d", val);

	if (strcmp (buf, gtk_entry_get_text (GTK_ENTRY (spin))))
		gtk_entry_set_text (GTK_ENTRY (spin), buf);

	g_free (buf);
	return TRUE;
}

static void
add_wired_page (NMConnectionEditor *editor)
{
	NMSettingWired *s_wired;
	GtkWidget *port;
	int port_idx = 0;
	GtkWidget *speed;
	int speed_idx = 0;
	GtkWidget *duplex;
	GtkWidget *autoneg;
	GtkWidget *mtu;
	int mtu_def;

	s_wired = NM_SETTING_WIRED (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_WIRED));
	g_return_if_fail (s_wired != NULL);

	add_page (editor, "WiredPage", _("Wired"));

	port = get_widget (editor, "wired_port");
	speed = get_widget (editor, "wired_speed");
	duplex = get_widget (editor, "wired_duplex");
	autoneg = get_widget (editor, "wired_autonegotiate");

	mtu = get_widget (editor, "wired_mtu");
	mtu_def = get_property_default (NM_SETTING (s_wired), NM_SETTING_WIRED_MTU);
	g_signal_connect (G_OBJECT (mtu), "output",
	                  (GCallback) spin_output_with_default,
	                  GINT_TO_POINTER (mtu_def));

	if (s_wired->port) {
		if (!strcmp (s_wired->port, "tp"))
			port_idx = 1;
		else if (!strcmp (s_wired->port, "aui"))
			port_idx = 2;
		else if (!strcmp (s_wired->port, "bnc"))
			port_idx = 3;
		else if (!strcmp (s_wired->port, "mii"))
			port_idx = 4;
	}
	gtk_combo_box_set_active (GTK_COMBO_BOX (port), port_idx);

	switch (s_wired->speed) {
	case 10:
		speed_idx = 1;
		break;
	case 100:
		speed_idx = 2;
		break;
	case 1000:
		speed_idx = 3;
		break;
	case 10000:
		speed_idx = 4;
		break;
	default:
		break;
	}
	gtk_combo_box_set_active (GTK_COMBO_BOX (speed), speed_idx);

	if (!strcmp (s_wired->duplex ? s_wired->duplex : "", "half"))
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (duplex), FALSE);
	else
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (duplex), TRUE);

	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (autoneg), s_wired->auto_negotiate);

	gtk_spin_button_set_value (GTK_SPIN_BUTTON (mtu), (gdouble) s_wired->mtu);

	/* FIXME: MAC address */
}

static gboolean
band_helper (NMConnectionEditor *editor, gboolean *aband, gboolean *gband)
{
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (get_widget (editor, "wireless_band")))) {
	case 1: /* A */
		*gband = FALSE;
		return TRUE;
	case 2: /* B/G */
		*aband = FALSE;
		return TRUE;
	default:
		return FALSE;
	}
}

static gint
channel_spin_input_cb (GtkSpinButton *spin, gdouble *new_val, gpointer user_data)
{
	NMConnectionEditor *editor = NM_CONNECTION_EDITOR (user_data);
	gdouble channel;
	guint32 int_channel = 0;
	gboolean aband = TRUE;
	gboolean gband = TRUE;

	if (!band_helper (editor, &aband, &gband))
		return GTK_INPUT_ERROR;

	channel = g_strtod (gtk_entry_get_text (GTK_ENTRY (spin)), NULL);
	if (channel - floor (channel) < ceil (channel) - channel)
		int_channel = floor (channel);
	else
		int_channel = ceil (channel);

	if (utils_channel_to_freq (int_channel, aband ? "a" : "bg") == -1)
		return GTK_INPUT_ERROR;

	*new_val = channel;
	return TRUE;
}

static gint
channel_spin_output_cb (GtkSpinButton *spin, gpointer user_data)
{
	NMConnectionEditor *editor = NM_CONNECTION_EDITOR (user_data);
	int channel;
	gchar *buf = NULL;
	guint32 freq;
	gboolean aband = TRUE;
	gboolean gband = TRUE;

	if (!band_helper (editor, &aband, &gband))
		buf = g_strdup (_("default"));
	else {
		channel = gtk_spin_button_get_value_as_int (spin);
		if (channel == 0)
			buf = g_strdup (_("default"));
		else {
			freq = utils_channel_to_freq (channel, aband ? "a" : "bg");
			if (freq == -1) {
				int direction = 0;

				if (editor->last_channel < channel)
					direction = 1;
				else if (editor->last_channel > channel)
					direction = -1;
				channel = utils_find_next_channel (channel, direction, aband ? "a" : "bg");
				freq = utils_channel_to_freq (channel, aband ? "a" : "bg");
				if (freq == -1) {
					g_warning ("%s: invalid channel %d!", __func__, channel);
					gtk_spin_button_set_value (spin, 0);
					goto out;
				}
			}
			buf = g_strdup_printf (_("%u (%u MHz)"), channel, freq);
		}
		editor->last_channel = channel;
	}

	if (strcmp (buf, gtk_entry_get_text (GTK_ENTRY (spin))))
		gtk_entry_set_text (GTK_ENTRY (spin), buf);

out:
	g_free (buf);
	return TRUE;
}

static void
band_value_changed_cb (GtkComboBox *box, gpointer user_data)
{
	NMConnectionEditor *editor = NM_CONNECTION_EDITOR (user_data);
	GtkWidget *widget;

	editor->last_channel = 0;

	widget = get_widget (editor, "wireless_channel");
	gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), 0);

	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (box))) {
	case 1: /* A */
	case 2: /* B/G */
		gtk_widget_set_sensitive (widget, TRUE);
		break;
	default:
		gtk_widget_set_sensitive (widget, FALSE);
		break;
	}
}

static void
add_wireless_page (NMConnectionEditor *editor)
{
	NMSettingWireless *s_wireless;
	int band_idx = 0;
	GtkWidget *mode;
	GtkWidget *band;
	GtkWidget *channel;
	GtkWidget *rate;
	int rate_def;
	GtkWidget *tx_power;
	int tx_power_def;
	GtkWidget *mtu;
	int mtu_def;

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_WIRELESS));
	g_return_if_fail (s_wireless != NULL);

	add_page (editor, "WirelessPage", _("Wireless"));

	rate = get_widget (editor, "wireless_rate");
	rate_def = get_property_default (NM_SETTING (s_wireless), NM_SETTING_WIRELESS_RATE);
	g_signal_connect (G_OBJECT (rate), "output",
	                  (GCallback) spin_output_with_default,
	                  GINT_TO_POINTER (rate_def));

	tx_power = get_widget (editor, "wireless_tx_power");
	tx_power_def = get_property_default (NM_SETTING (s_wireless), NM_SETTING_WIRELESS_TX_POWER);
	g_signal_connect (G_OBJECT (tx_power), "output",
	                  (GCallback) spin_output_with_default,
	                  GINT_TO_POINTER (tx_power_def));

	mtu = get_widget (editor, "wireless_mtu");
	mtu_def = get_property_default (NM_SETTING (s_wireless), NM_SETTING_WIRELESS_MTU);
	g_signal_connect (G_OBJECT (mtu), "output",
	                  (GCallback) spin_output_with_default,
	                  GINT_TO_POINTER (mtu_def));

	/* FIXME: SSID */

	mode = get_widget (editor, "wireless_mode");
	if (!strcmp (s_wireless->mode ? s_wireless->mode : "", "infrastructure"))
		gtk_combo_box_set_active (GTK_COMBO_BOX (mode), 0);
	else if (!strcmp (s_wireless->mode ? s_wireless->mode : "", "adhoc"))
		gtk_combo_box_set_active (GTK_COMBO_BOX (mode), 1);
	else
		gtk_combo_box_set_active (GTK_COMBO_BOX (mode), -1);

	channel = get_widget (editor, "wireless_channel");
	g_signal_connect (G_OBJECT (channel), "output",
	                  (GCallback) channel_spin_output_cb,
	                  editor);
	g_signal_connect (G_OBJECT (channel), "input",
	                  (GCallback) channel_spin_input_cb,
	                  editor);

	gtk_widget_set_sensitive (channel, FALSE);
	if (s_wireless->band) {
		if (!strcmp (s_wireless->band ? s_wireless->band : "", "a")) {
			band_idx = 1;
			gtk_widget_set_sensitive (channel, TRUE);
		} else if (!strcmp (s_wireless->band ? s_wireless->band : "", "bg")) {
			band_idx = 2;
			gtk_widget_set_sensitive (channel, TRUE);
		}
	}
	band = get_widget (editor, "wireless_band");
	gtk_combo_box_set_active (GTK_COMBO_BOX (band), band_idx);
	g_signal_connect (G_OBJECT (band), "changed",
	                  (GCallback) band_value_changed_cb,
	                  editor);

	/* Update the channel _after_ the band has been set so that it gets
	 * the right values */
	editor->last_channel = s_wireless->channel;
	gtk_spin_button_set_value (GTK_SPIN_BUTTON (channel), (gdouble) s_wireless->channel);

	/* FIXME: BSSID */
	/* FIXME: MAC address */

	gtk_spin_button_set_value (GTK_SPIN_BUTTON (rate), (gdouble) s_wireless->rate);
	gtk_spin_button_set_value (GTK_SPIN_BUTTON (tx_power), (gdouble) s_wireless->tx_power);
	gtk_spin_button_set_value (GTK_SPIN_BUTTON (mtu), (gdouble) s_wireless->mtu);
}

static void
add_ip4_pages (NMConnectionEditor *editor)
{
	NMSettingIP4Config *s_ip4;

	add_page (editor, "IP4Page", _("IPv4 Settings"));
	add_page (editor, "IP4AddressPage", _("IPv4 Addresses"));

	s_ip4 = NM_SETTING_IP4_CONFIG (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_IP4_CONFIG));
	if (s_ip4) {
	} else {
	}
}

static NMUtilsSecurityType
get_default_type_for_security (NMSettingWirelessSecurity *sec)
{
	if (!sec)
		return NMU_SEC_NONE;

	/* No IEEE 802.1x */
	if (!strcmp (sec->key_mgmt, "none")) {
		/* Static WEP */
		if (   sec->wep_tx_keyidx
		    || sec->wep_key0
		    || sec->wep_key1
		    || sec->wep_key2
		    || sec->wep_key3
		    || (sec->auth_alg && !strcmp (sec->auth_alg, "shared")))
			return NMU_SEC_STATIC_WEP;

		/* Unencrypted */
		return NMU_SEC_NONE;
	}

	if (!strcmp (sec->key_mgmt, "ieee8021x")) {
		if (sec->auth_alg && !strcmp (sec->auth_alg, "leap"))
			return NMU_SEC_LEAP;
		return NMU_SEC_DYNAMIC_WEP;
	}

	if (   !strcmp (sec->key_mgmt, "wpa-none")
	    || !strcmp (sec->key_mgmt, "wpa-psk")) {
		if (sec->proto && !strcmp (sec->proto->data, "rsn"))
			return NMU_SEC_WPA2_PSK;
		else if (sec->proto && !strcmp (sec->proto->data, "wpa"))
			return NMU_SEC_WPA_PSK;
		else
			return NMU_SEC_WPA_PSK;
	}

	if (!strcmp (sec->key_mgmt, "wpa-eap")) {
		if (sec->proto && !strcmp (sec->proto->data, "rsn"))
			return NMU_SEC_WPA2_ENTERPRISE;
		else if (sec->proto && !strcmp (sec->proto->data, "wpa"))
			return NMU_SEC_WPA_ENTERPRISE;
		else
			return NMU_SEC_WPA_ENTERPRISE;
	}

	return NMU_SEC_INVALID;
}

static void
stuff_changed_cb (WirelessSecurity *sec, gpointer user_data)
{
	NMConnectionEditor *editor = NM_CONNECTION_EDITOR (user_data);
	GtkWidget *widget;
	gboolean valid = FALSE;
	NMSettingWireless *s_wireless;

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_WIRELESS));
	g_assert (s_wireless);

	valid = wireless_security_validate (sec, s_wireless->ssid);
	widget = get_widget (editor, "ok_button");
	gtk_widget_set_sensitive (widget, valid);
}

static void
wsec_size_group_clear (GtkSizeGroup *group)
{
	GSList *children;
	GSList *iter;

	g_return_if_fail (group != NULL);

	children = gtk_size_group_get_widgets (group);
	for (iter = children; iter; iter = g_slist_next (iter))
		gtk_size_group_remove_widget (group, GTK_WIDGET (iter->data));
}

static void
wireless_security_combo_changed (GtkWidget *combo,
                                 gpointer user_data)
{
	NMConnectionEditor *editor = NM_CONNECTION_EDITOR (user_data);
	GtkWidget *vbox;
	GList *elt, *children;
	GtkTreeIter iter;
	GtkTreeModel *model;
	WirelessSecurity *sec = NULL;

	vbox = get_widget (editor, "wireless_security_vbox");
	g_assert (vbox);

	wsec_size_group_clear (editor->wsec_group);

	/* Remove any previous wireless security widgets */
	children = gtk_container_get_children (GTK_CONTAINER (vbox));
	for (elt = children; elt; elt = g_list_next (elt))
		gtk_container_remove (GTK_CONTAINER (vbox), GTK_WIDGET (elt->data));

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter);
	gtk_tree_model_get (model, &iter, S_SEC_COLUMN, &sec, -1);
	if (sec) {
		GtkWidget *sec_widget;
		GtkWidget *widget;

		sec_widget = wireless_security_get_widget (sec);
		g_assert (sec_widget);

		widget = get_widget (editor, "wireless_security_combo_label");
		gtk_size_group_add_widget (editor->wsec_group, widget);
		wireless_security_add_to_size_group (sec, editor->wsec_group);

		gtk_container_add (GTK_CONTAINER (vbox), sec_widget);
		wireless_security_unref (sec);
	}
}

static void
add_security_item (NMConnectionEditor *editor,
                   WirelessSecurity *sec,
                   GtkListStore *model,
                   GtkTreeIter *iter,
                   const char *text)
{
	wireless_security_set_changed_notify (sec, stuff_changed_cb, editor);
	gtk_list_store_append (model, iter);
	gtk_list_store_set (model, iter, S_NAME_COLUMN, text, S_SEC_COLUMN, sec, -1);
	wireless_security_unref (sec);
}

static void
add_wireless_security_page (NMConnectionEditor *editor, NMConnection *connection)
{
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;
	gboolean is_adhoc = FALSE;
	GtkListStore *sec_model;
	GtkTreeIter iter;
	guint32 dev_caps = 0;
	NMUtilsSecurityType default_type = NMU_SEC_NONE;
	int active = -1;
	int item = 0;
	const char *glade_file = GLADEDIR "/applet.glade";
	GtkWidget *combo;

	add_page (editor, "WirelessSecurityPage", _("Wireless Security"));

	combo = get_widget (editor, "wireless_security_combo");

	dev_caps =   NM_802_11_DEVICE_CAP_CIPHER_WEP40
	           | NM_802_11_DEVICE_CAP_CIPHER_WEP104
	           | NM_802_11_DEVICE_CAP_CIPHER_TKIP
	           | NM_802_11_DEVICE_CAP_CIPHER_CCMP
	           | NM_802_11_DEVICE_CAP_WPA
	           | NM_802_11_DEVICE_CAP_RSN;

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	g_assert (s_wireless);

	if (s_wireless->mode && !strcmp (s_wireless->mode, "adhoc"))
		is_adhoc = TRUE;

	s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, 
	                                               NM_TYPE_SETTING_WIRELESS_SECURITY));
	default_type = get_default_type_for_security (s_wireless_sec);

	sec_model = gtk_list_store_new (2, G_TYPE_STRING, wireless_security_get_g_type ());

	if (nm_utils_security_valid (NMU_SEC_NONE, dev_caps, FALSE, is_adhoc, 0, 0, 0)) {
		gtk_list_store_append (sec_model, &iter);
		gtk_list_store_set (sec_model, &iter,
		                    S_NAME_COLUMN, _("None"),
		                    -1);
		if (default_type == NMU_SEC_NONE)
			active = item;
	}

	if (nm_utils_security_valid (NMU_SEC_STATIC_WEP, dev_caps, FALSE, is_adhoc, 0, 0, 0)) {
		WirelessSecurityWEPKey *ws_wep_hex;
		WirelessSecurityWEPKey *ws_wep_ascii;
		WirelessSecurityWEPPassphrase *ws_wep_passphrase;

		ws_wep_passphrase = ws_wep_passphrase_new (glade_file, connection);
		if (ws_wep_passphrase) {
			add_security_item (editor, WIRELESS_SECURITY (ws_wep_passphrase), sec_model,
			                   &iter, _("WEP 128-bit Passphrase"));
			if ((active < 0) && (default_type == NMU_SEC_STATIC_WEP))
				active = item++;
		}

		ws_wep_hex = ws_wep_key_new (glade_file, connection, WEP_KEY_TYPE_HEX);
		if (ws_wep_hex) {
			add_security_item (editor, WIRELESS_SECURITY (ws_wep_hex), sec_model,
			                   &iter, _("WEP 40/128-bit Hexadecimal"));
			if ((active < 0) && (default_type == NMU_SEC_STATIC_WEP))
				active = item++;
		}

		ws_wep_ascii = ws_wep_key_new (glade_file, connection, WEP_KEY_TYPE_ASCII);
		if (ws_wep_ascii) {
			add_security_item (editor, WIRELESS_SECURITY (ws_wep_ascii), sec_model,
			                   &iter, _("WEP 40/128-bit ASCII"));
			if ((active < 0) && (default_type == NMU_SEC_STATIC_WEP))
				active = item++;
		}
	}

	if (nm_utils_security_valid (NMU_SEC_LEAP, dev_caps, FALSE, is_adhoc, 0, 0, 0)) {
		WirelessSecurityLEAP *ws_leap;

		ws_leap = ws_leap_new (glade_file, connection);
		if (ws_leap) {
			add_security_item (editor, WIRELESS_SECURITY (ws_leap), sec_model,
			                   &iter, _("LEAP"));
			if ((active < 0) && (default_type == NMU_SEC_LEAP))
				active = item++;
		}
	}

	if (nm_utils_security_valid (NMU_SEC_DYNAMIC_WEP, dev_caps, FALSE, is_adhoc, 0, 0, 0)) {
		WirelessSecurityDynamicWEP *ws_dynamic_wep;

		ws_dynamic_wep = ws_dynamic_wep_new (glade_file, connection);
		if (ws_dynamic_wep) {
			add_security_item (editor, WIRELESS_SECURITY (ws_dynamic_wep), sec_model,
			                   &iter, _("Dynamic WEP (802.1x)"));
			if ((active < 0) && (default_type == NMU_SEC_DYNAMIC_WEP))
				active = item++;
		}
	}

	if (   nm_utils_security_valid (NMU_SEC_WPA_PSK, dev_caps, FALSE, is_adhoc, 0, 0, 0)
	    || nm_utils_security_valid (NMU_SEC_WPA2_PSK, dev_caps, FALSE, is_adhoc, 0, 0, 0)) {
		WirelessSecurityWPAPSK *ws_wpa_psk;

		ws_wpa_psk = ws_wpa_psk_new (glade_file, connection);
		if (ws_wpa_psk) {
			add_security_item (editor, WIRELESS_SECURITY (ws_wpa_psk), sec_model,
			                   &iter, _("WPA & WPA2 Personal"));
			if ((active < 0) && ((default_type == NMU_SEC_WPA_PSK) || (default_type == NMU_SEC_WPA2_PSK)))
				active = item++;
		}
	}

	if (   nm_utils_security_valid (NMU_SEC_WPA_ENTERPRISE, dev_caps, FALSE, is_adhoc, 0, 0, 0)
	    || nm_utils_security_valid (NMU_SEC_WPA2_ENTERPRISE, dev_caps, FALSE, is_adhoc, 0, 0, 0)) {
		WirelessSecurityWPAEAP *ws_wpa_eap;

		ws_wpa_eap = ws_wpa_eap_new (glade_file, connection);
		if (ws_wpa_eap) {
			add_security_item (editor, WIRELESS_SECURITY (ws_wpa_eap), sec_model,
			                   &iter, _("WPA & WPA2 Enterprise"));
			if ((active < 0) && ((default_type == NMU_SEC_WPA_ENTERPRISE) || (default_type == NMU_SEC_WPA2_ENTERPRISE)))
				active = item++;
		}
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (sec_model));
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), active < 0 ? 0 : (guint32) active);
	g_object_unref (G_OBJECT (sec_model));

	wireless_security_combo_changed (combo, editor);
	g_signal_connect (G_OBJECT (combo),
	                  "changed",
	                  GTK_SIGNAL_FUNC (wireless_security_combo_changed),
	                  editor);
}

void
nm_connection_editor_set_connection (NMConnectionEditor *editor, NMConnection *connection)
{
	NMSettingConnection *s_con;
//	GtkWidget *widget;

	g_return_if_fail (NM_IS_CONNECTION_EDITOR (editor));
	g_return_if_fail (connection != NULL);

	/* clean previous connection */
	if (editor->connection) {
		g_object_unref (G_OBJECT (editor->connection));
		editor->connection = NULL;
	}

	editor->connection = (NMConnection *) g_object_ref (connection);
	nm_connection_editor_update_title (editor);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (!strcmp (s_con->type, NM_SETTING_WIRED_SETTING_NAME)) {
		add_wired_page (editor);
		add_ip4_pages (editor);
	} else if (!strcmp (s_con->type, NM_SETTING_WIRELESS_SETTING_NAME)) {
		add_wireless_page (editor);
		add_wireless_security_page (editor, connection);
		add_ip4_pages (editor);
	} else if (!strcmp (s_con->type, NM_SETTING_VPN_SETTING_NAME)) {
		add_ip4_pages (editor);
	} else {
		g_warning ("Unhandled setting type '%s'", s_con->type);
	}

	/* set the UI */
	fill_connection_values (editor);
}

void
nm_connection_editor_show (NMConnectionEditor *editor)
{
	g_return_if_fail (NM_IS_CONNECTION_EDITOR (editor));

	gtk_widget_show (editor->dialog);
}

gint
nm_connection_editor_run_and_close (NMConnectionEditor *editor)
{
	gint result;

	g_return_val_if_fail (NM_IS_CONNECTION_EDITOR (editor), GTK_RESPONSE_CANCEL);

	result = gtk_dialog_run (GTK_DIALOG (editor->dialog));
	gtk_widget_hide (editor->dialog);

	return result;
}
