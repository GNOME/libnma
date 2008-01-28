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

#include <gtk/gtk.h>
#include <gtk/gtkcombobox.h>
#include <gtk/gtkdialog.h>
#include <gtk/gtkentry.h>
#include <gtk/gtkspinbutton.h>
#include <gtk/gtktogglebutton.h>
#include <gtk/gtknotebook.h>
#include <gtk/gtklabel.h>
#include <gtk/gtkmessagedialog.h>
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

#include "page-wired.h"
#include "page-wireless.h"
#include "page-wireless-security.h"
#include "page-ip4.h"
#include "page-ip4-address.h"

G_DEFINE_TYPE (NMConnectionEditor, nm_connection_editor, G_TYPE_OBJECT)

static void
dialog_response_cb (GtkDialog *dialog, guint response, gpointer user_data)
{
	gtk_widget_hide (GTK_WIDGET (dialog));
}

int
ce_get_property_default (NMSetting *setting, const char *property_name)
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

static void
add_page (NMConnectionEditor *editor,
          GtkWidget *page,
          const char *title)
{
	GtkWidget *notebook;
	GtkWidget *label;

	notebook = glade_xml_get_widget (editor->xml, "notebook");
	label = gtk_label_new (title);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), page, label);
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

static void
nm_connection_editor_init (NMConnectionEditor *editor)
{
	GtkWidget *widget;
	GtkWidget *dialog;

	if (!g_file_test (GLADEDIR "/applet.glade", G_FILE_TEST_EXISTS)) {
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

	editor->xml = glade_xml_new (GLADEDIR "/nm-connection-editor.glade", NULL, NULL);
	if (!editor->xml) {
		dialog = gtk_message_dialog_new (NULL, 0,
		                                 GTK_MESSAGE_ERROR,
		                                 GTK_BUTTONS_OK,
		                                 "%s",
		                                 _("The connection editor could not find some required resources (the glade file was not found)."));
		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
		gtk_main_quit ();
		return;
	}

	editor->dialog = glade_xml_get_widget (editor->xml, "NMConnectionEditor");
	g_signal_connect (G_OBJECT (editor->dialog), "response", G_CALLBACK (dialog_response_cb), editor);

	widget = glade_xml_get_widget (editor->xml, "connection_name");
	g_signal_connect (G_OBJECT (widget), "changed",
	                  G_CALLBACK (connection_name_changed), editor);
}

static void
nm_connection_editor_finalize (GObject *object)
{
	NMConnectionEditor *editor = NM_CONNECTION_EDITOR (object);

	if (editor->connection)
		g_object_unref (editor->connection);

	gtk_widget_destroy (editor->dialog);
	g_object_unref (editor->xml);

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

gint
ce_spin_output_with_default (GtkSpinButton *spin, gpointer user_data)
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
fill_connection_values (NMConnectionEditor *editor)
{
	NMSettingConnection *s_con;
	GtkWidget *name;
	GtkWidget *autoconnect;

	name = glade_xml_get_widget (editor->xml, "connection_name");
	autoconnect = glade_xml_get_widget (editor->xml, "connection_autoconnect");

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (editor->connection, NM_TYPE_SETTING_CONNECTION));
	if (s_con) {
		gtk_entry_set_text (GTK_ENTRY (name), s_con->id);
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (autoconnect), s_con->autoconnect);
	} else {
		gtk_entry_set_text (GTK_ENTRY (name), NULL);
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (autoconnect), FALSE);
	}
}

void
nm_connection_editor_set_connection (NMConnectionEditor *editor, NMConnection *connection)
{
	NMSettingConnection *s_con;
	GtkWidget *widget;
	char *title = NULL;
	GtkWidget *ok_button;

	g_return_if_fail (NM_IS_CONNECTION_EDITOR (editor));
	g_return_if_fail (connection != NULL);

	/* clean previous connection */
	if (editor->connection) {
		g_object_unref (G_OBJECT (editor->connection));
		editor->connection = NULL;
	}

	editor->connection = (NMConnection *) g_object_ref (connection);
	nm_connection_editor_update_title (editor);

	ok_button = glade_xml_get_widget (editor->xml, "ok_button");

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (!strcmp (s_con->type, NM_SETTING_WIRED_SETTING_NAME)) {
		widget = page_wired_new (editor->connection, (const char **) &title);
		if (widget)
			add_page (editor, widget, title);

		widget = page_ip4_address_new (editor->connection, (const char **) &title);
		if (widget)
			add_page (editor, widget, title);

		widget = page_ip4_new (editor->connection, (const char **) &title);
		if (widget)
			add_page (editor, widget, title);
	} else if (!strcmp (s_con->type, NM_SETTING_WIRELESS_SETTING_NAME)) {
		GtkWidget *wireless_page;

		wireless_page = page_wireless_new (editor->connection, (const char **) &title);
		if (wireless_page)
			add_page (editor, wireless_page, title);

		widget = page_wireless_security_new (editor->connection, ok_button, wireless_page, (const char **) &title);
		if (widget)
			add_page (editor, widget, title);

		widget = page_ip4_address_new (editor->connection, (const char **) &title);
		if (widget)
			add_page (editor, widget, title);

		widget = page_ip4_new (editor->connection, (const char **) &title);
		if (widget)
			add_page (editor, widget, title);
	} else if (!strcmp (s_con->type, NM_SETTING_VPN_SETTING_NAME)) {
		widget = page_ip4_address_new (editor->connection, (const char **) &title);
		if (widget)
			add_page (editor, widget, title);

		widget = page_ip4_new (editor->connection, (const char **) &title);
		if (widget)
			add_page (editor, widget, title);
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
