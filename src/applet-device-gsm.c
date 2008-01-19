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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n.h>
#include <gtk/gtkwidget.h>
#include <gtk/gtkmenuitem.h>
#include <gtk/gtkcheckmenuitem.h>

#include <nm-device.h>
#include <nm-setting-connection.h>
#include <nm-setting-gsm.h>
#include <nm-setting-serial.h>
#include <nm-setting-ppp.h>
#include <nm-gsm-device.h>

#include "applet.h"
#include "applet-dbus-settings.h"
#include "applet-device-gsm.h"
#include "utils.h"

typedef struct {
	NMApplet *applet;
	NMDevice *device;
	NMConnection *connection;
} GSMMenuItemInfo;

static void
gsm_menu_item_info_destroy (gpointer data)
{
	g_slice_free (GSMMenuItemInfo, data);
}

static NMConnection *
gsm_new_auto_connection (NMDevice *device,
                         NMApplet *applet,
                         gpointer user_data)
{
	NMConnection *connection;
	NMSettingGsm *s_gsm;
	NMSettingSerial *s_serial;
	NMSettingPPP *s_ppp;
	NMSettingConnection *s_con;

	connection = nm_connection_new ();

	s_gsm = NM_SETTING_GSM (nm_setting_gsm_new ());
	s_gsm->number = g_strdup ("*99#"); /* This should be a sensible default as it's seems to be quite standard */

	/* Serial setting */
	s_serial = (NMSettingSerial *) nm_setting_serial_new ();
	s_serial->baud = 115200;
	s_serial->bits = 8;
	s_serial->parity = 'n';
	s_serial->stopbits = 1;
	nm_connection_add_setting (connection, NM_SETTING (s_serial));

	s_ppp = (NMSettingPPP *) nm_setting_ppp_new ();
	s_ppp->usepeerdns = TRUE; /* This is probably a good default as well */
	nm_connection_add_setting (connection, NM_SETTING (s_ppp));

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	s_con->id = g_strdup (_("Auto GSM dialup connection"));
	s_con->type = g_strdup (NM_SETTING (s_gsm)->name);
	s_con->autoconnect = FALSE;
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	return connection;
}

static void
gsm_menu_item_activate (GtkMenuItem *item, gpointer user_data)
{
	GSMMenuItemInfo *info = (GSMMenuItemInfo *) user_data;

	applet_menu_item_activate_helper (info->device,
	                                  info->connection,
	                                  "/",
	                                  info->applet,
	                                  user_data);
}

static void
add_connection_items (NMDevice *device,
                      GSList *connections,
                      NMConnection *active,
                      GtkWidget *menu,
                      NMApplet *applet)
{
	GSList *iter;
	GSMMenuItemInfo *info;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;
		GtkWidget *item;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
		item = gtk_check_menu_item_new_with_label (s_con->id);
		gtk_check_menu_item_set_draw_as_radio (GTK_CHECK_MENU_ITEM (item), TRUE);

		if (connection == active)
			gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (item), TRUE);

		info = g_slice_new0 (GSMMenuItemInfo);
		info->applet = applet;
		info->device = g_object_ref (G_OBJECT (device));
		info->connection = g_object_ref (connection);

		g_signal_connect_data (item, "activate",
		                       G_CALLBACK (gsm_menu_item_activate),
		                       info,
		                       (GClosureNotify) gsm_menu_item_info_destroy, 0);

		gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
	}
}

static void
gsm_add_menu_item (NMDevice *device,
                   guint32 n_devices,
                   NMConnection *active,
                   GtkWidget *menu,
                   NMApplet *applet)
{
	char *text;
	GtkWidget *item;
	GSList *connections, *all;

	all = applet_dbus_settings_get_all_connections (APPLET_DBUS_SETTINGS (applet->settings));
	connections = utils_filter_connections_for_device (device, all);
	g_slist_free (all);

	if (n_devices > 1) {
		const char *desc;
		char *dev_name = NULL;

		desc = utils_get_device_description (device);
		if (desc)
			dev_name = g_strdup (desc);
		if (!dev_name)
			dev_name = nm_device_get_iface (device);
		g_assert (dev_name);

		if (g_slist_length (connections) > 1)
			text = g_strdup_printf (_("GSM Connections (%s)"), dev_name);
		else
			text = g_strdup_printf (_("GSM Modem (%s)"), dev_name);
		g_free (dev_name);
	} else {
		if (g_slist_length (connections) > 1)
			text = g_strdup (_("GSM Connections"));
		else
			text = g_strdup (_("_GSM Modem"));
	}

	if (g_slist_length (connections) > 1) {
		item = gtk_menu_item_new_with_label (text);
	} else {
		item = gtk_check_menu_item_new_with_mnemonic (text);
		gtk_check_menu_item_set_draw_as_radio (GTK_CHECK_MENU_ITEM (item), TRUE);
	}
	g_free (text);

	gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);

	if (g_slist_length (connections) > 1) {
		GtkWidget *label;
		char *bold_text;

		label = gtk_bin_get_child (GTK_BIN (item));
		bold_text = g_markup_printf_escaped ("<span weight=\"bold\">%s</span>",
		                                     gtk_label_get_text (GTK_LABEL (label)));
		gtk_label_set_markup (GTK_LABEL (label), bold_text);
		g_free (bold_text);

		gtk_widget_set_sensitive (item, FALSE);

		add_connection_items (device, connections, active, menu, applet);
	} else {
		GSMMenuItemInfo *info;
		NMConnection *connection;

		info = g_slice_new0 (GSMMenuItemInfo);
		info->applet = applet;
		info->device = g_object_ref (G_OBJECT (device));

		if (g_slist_length (connections) == 1) {
			connection = NM_CONNECTION (g_slist_nth_data (connections, 0));
			info->connection = g_object_ref (G_OBJECT (connection));
		}

		if (   (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED)
		    || (info->connection && info->connection == active))
			gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (item), TRUE);

		g_signal_connect_data (item, "activate",
		                       G_CALLBACK (gsm_menu_item_activate),
		                       info,
		                       (GClosureNotify) gsm_menu_item_info_destroy, 0);
	}

	gtk_widget_show (item);
	g_slist_free (connections);
}

static void
gsm_device_state_changed (NMDevice *device,
                          NMDeviceState state,
                          NMApplet *applet)
{
	if (state == NM_DEVICE_STATE_ACTIVATED) {
		applet_do_notify (applet, NOTIFY_URGENCY_LOW,
					      _("Connection Established"),
						  _("You are now connected to the GSM network."),
						  "nm-adhoc");
	}
}

static GdkPixbuf *
gsm_get_icon (NMDevice *device,
              NMDeviceState state,
              char **tip,
              NMApplet *applet)
{
	GdkPixbuf *pixbuf = NULL;
	char *iface;

	iface = nm_device_get_iface (NM_DEVICE (device));

	switch (state) {
	case NM_DEVICE_STATE_PREPARE:
		*tip = g_strdup_printf (_("Dialing GSM device %s..."), iface);
		break;
	case NM_DEVICE_STATE_CONFIG:
		*tip = g_strdup_printf (_("Running PPP on device %s..."), iface);
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		*tip = g_strdup (_("GSM connection"));
		// FIXME: get a real icon
		pixbuf = applet->adhoc_icon;
		break;
	default:
		break;
	}

	g_free (iface);
	return pixbuf;
}

NMADeviceClass *
applet_device_gsm_get_class (NMApplet *applet)
{
	NMADeviceClass *dclass;

	dclass = g_slice_new0 (NMADeviceClass);
	if (!dclass)
		return NULL;

	dclass->new_auto_connection = gsm_new_auto_connection;
	dclass->add_menu_item = gsm_add_menu_item;
	dclass->device_state_changed = gsm_device_state_changed;
	dclass->get_icon = gsm_get_icon;

	return dclass;
}

