/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
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
 * This applet used the GNOME Wireless Applet as a skeleton to build from.
 *
 * GNOME Wireless Applet Authors:
 *		Eskil Heyn Olsen <eskil@eskil.dk>
 *		Bastien Nocera <hadess@hadess.net> (Gnome2 port)
 *
 * (C) Copyright 2004-2005 Red Hat, Inc.
 * (C) Copyright 2001, 2002 Free Software Foundation
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <gtk/gtk.h>
#include <glib/gi18n.h>
#include <iwlib.h>
#include <wireless.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <nm-device-802-3-ethernet.h>
#include <nm-device-802-11-wireless.h>

#include <glade/glade.h>
#include <gconf/gconf-client.h>

#ifdef ENABLE_NOTIFY
#include <libnotify/notify.h>
#endif

#include "applet.h"
#include "applet-notifications.h"
#include "menu-items.h"
#include "vpn-password-dialog.h"
#include "nm-utils.h"
#include "gnome-keyring-md5.h"
#include "applet-dbus-manager.h"

#include "nm-connection.h"
#include "vpn-connection-info.h"

/* Compat for GTK 2.6 */
#if (GTK_MAJOR_VERSION <= 2 && GTK_MINOR_VERSION == 6)
	#define GTK_STOCK_INFO			GTK_STOCK_DIALOG_INFO
#endif

static GObject *			nma_constructor (GType type, guint n_props, GObjectConstructParam *construct_props);
static void			nma_icons_init (NMApplet *applet);
static void				nma_icons_free (NMApplet *applet);
static void				nma_icons_zero (NMApplet *applet);
static gboolean			nma_icons_load_from_disk (NMApplet *applet);
static void			nma_finalize (GObject *object);
static void              foo_set_icon (NMApplet *applet, GdkPixbuf *pixbuf, guint32 layer);

static GtkWidget *
nma_menu_create (GtkMenuItem *parent, NMApplet *applet);

G_DEFINE_TYPE(NMApplet, nma, G_TYPE_OBJECT)

/* Shamelessly ripped from the Linux kernel ieee80211 stack */
gboolean
nma_is_empty_ssid (const char * ssid, int len)
{
        /* Single white space is for Linksys APs */
        if (len == 1 && ssid[0] == ' ')
                return TRUE;

        /* Otherwise, if the entire ssid is 0, we assume it is hidden */
        while (len--) {
                if (ssid[len] != '\0')
                        return FALSE;
        }
        return TRUE;
}

const char *
nma_escape_ssid (const char * ssid, guint32 len)
{
	static char escaped[IW_ESSID_MAX_SIZE * 2 + 1];
	const char *s = ssid;
	char *d = escaped;

	if (nma_is_empty_ssid (ssid, len)) {
		memcpy (escaped, "<hidden>", sizeof ("<hidden>"));
		return escaped;
	}

	len = MIN (len, (guint32) IW_ESSID_MAX_SIZE);
	while (len--) {
		if (*s == '\0') {
			*d++ = '\\';
			*d++ = '0';
			s++;
		} else {
			*d++ = *s++;
		}
	}
	*d = '\0';
	return escaped;
}


static NMDevice *
get_first_active_device (NMApplet *applet)
{
	GSList *list;
	GSList *iter;
	NMDevice *active_device = NULL;

	list = nm_client_get_devices (applet->nm_client);
	for (iter = list; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED) {
			active_device = device;
			break;
		}
	}

	g_slist_free (list);

	return active_device;
}

static void nma_init (NMApplet *applet)
{
	applet->animation_id = 0;
	applet->animation_step = 0;
	applet->passphrase_dialog = NULL;
	applet->icon_theme = NULL;
#ifdef ENABLE_NOTIFY
	applet->notification = NULL;
#endif
#ifdef HAVE_STATUS_ICON
	applet->size = -1;
#endif

	nma_icons_zero (applet);

/*	gtk_window_set_default_icon_from_file (ICONDIR"/NMApplet/wireless-applet.png", NULL); */
}

static void nma_class_init (NMAppletClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructor = nma_constructor;
	gobject_class->finalize = nma_finalize;
}

static GtkWidget * get_label (GtkWidget *info_dialog, GladeXML *xml, const char *name)
{
	GtkWidget *label;

	if (xml != NULL)
	{
		label = glade_xml_get_widget (xml, name);
		g_object_set_data (G_OBJECT (info_dialog), name, label);
	}
	else
		label = g_object_get_data (G_OBJECT (info_dialog), name);

	return label;
}

static void nma_show_socket_err (GtkWidget *info_dialog, const char *err)
{
	GtkWidget *error_dialog;

	error_dialog = gtk_message_dialog_new_with_markup (GTK_WINDOW (info_dialog), 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
			"<span weight=\"bold\" size=\"larger\">%s</span>\n\n%s", _("Error displaying connection information:"), err);
	gtk_window_present (GTK_WINDOW (error_dialog));
	g_signal_connect_swapped (error_dialog, "response", G_CALLBACK (gtk_widget_destroy), error_dialog);
}

static const gchar *
ip4_address_as_string (guint32 ip)
{
	struct in_addr tmp_addr;
	gchar *ip_string;

	tmp_addr.s_addr = ip;
	ip_string = inet_ntoa (tmp_addr);

	return ip_string;
}

static gboolean
nma_update_info (NMApplet *applet)
{
	GtkWidget *info_dialog;
	GtkWidget *label;
	NMDevice *device;
	NMIP4Config *cfg;
	int speed;
	char *str;
	char *iface_and_type;
	GArray *dns;

	info_dialog = glade_xml_get_widget (applet->info_dialog_xml, "info_dialog");
	if (!info_dialog) {
		nma_show_socket_err (info_dialog, "Could not find some required resources (the glade file)!");
		return FALSE;
	}

	device = get_first_active_device (applet);
	if (!device) {
		nma_show_socket_err (info_dialog, _("No active connections!"));
		return FALSE;
	}

	cfg = nm_device_get_ip4_config (device);

	speed = 0;
	if (NM_IS_DEVICE_802_3_ETHERNET (device))
		speed = nm_device_802_3_ethernet_get_speed (NM_DEVICE_802_3_ETHERNET (device));
	else if (NM_IS_DEVICE_802_11_WIRELESS (device))
		speed = nm_device_802_11_wireless_get_bitrate (NM_DEVICE_802_11_WIRELESS (device));

	str = nm_device_get_iface (device);
	if (NM_IS_DEVICE_802_3_ETHERNET (device))
		iface_and_type = g_strdup_printf (_("Wired Ethernet (%s)"), str);
	else if (NM_IS_DEVICE_802_11_WIRELESS (device))
		iface_and_type = g_strdup_printf (_("Wireless Ethernet (%s)"), str);
	else
		iface_and_type = g_strdup (str);

	g_free (str);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-interface");
	gtk_label_set_text (GTK_LABEL (label), iface_and_type);
	g_free (iface_and_type);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-speed");
	if (speed) {
		str = g_strdup_printf (_("%d Mb/s"), speed);
		gtk_label_set_text (GTK_LABEL (label), str);
		g_free (str);
	} else
		gtk_label_set_text (GTK_LABEL (label), _("Unknown"));

	str = nm_device_get_driver (device);
	label = get_label (info_dialog, applet->info_dialog_xml, "label-driver");
	gtk_label_set_text (GTK_LABEL (label), str);
	g_free (str);

	label = get_label (info_dialog, applet->info_dialog_xml, "label-ip-address");
	gtk_label_set_text (GTK_LABEL (label),
					ip4_address_as_string (nm_ip4_config_get_address (cfg)));

	label = get_label (info_dialog, applet->info_dialog_xml, "label-broadcast-address");
	gtk_label_set_text (GTK_LABEL (label),
					ip4_address_as_string (nm_ip4_config_get_broadcast (cfg)));

	label = get_label (info_dialog, applet->info_dialog_xml, "label-subnet-mask");
	gtk_label_set_text (GTK_LABEL (label),
					ip4_address_as_string (nm_ip4_config_get_netmask (cfg)));

	label = get_label (info_dialog, applet->info_dialog_xml, "label-default-route");
	gtk_label_set_text (GTK_LABEL (label),
					ip4_address_as_string (nm_ip4_config_get_gateway (cfg)));

	dns = nm_ip4_config_get_nameservers (cfg);
	if (dns) {
		if (dns->len > 0) {
			label = get_label (info_dialog, applet->info_dialog_xml, "label-primary-dns");
			gtk_label_set_text (GTK_LABEL (label),
							ip4_address_as_string (g_array_index (dns, guint32, 0)));
		}

		if (dns->len > 1) {
			label = get_label (info_dialog, applet->info_dialog_xml, "label-secondary-dns");
			gtk_label_set_text (GTK_LABEL (label),
							ip4_address_as_string (g_array_index (dns, guint32, 0)));
		}

		g_array_free (dns, TRUE);
	}

	str = NULL;
	if (NM_IS_DEVICE_802_3_ETHERNET (device))
		str = nm_device_802_3_ethernet_get_hw_address (NM_DEVICE_802_3_ETHERNET (device));
	else if (NM_IS_DEVICE_802_11_WIRELESS (device))
		str = nm_device_802_11_wireless_get_hw_address (NM_DEVICE_802_11_WIRELESS (device));

	if (str) {
		label = get_label (info_dialog, applet->info_dialog_xml, "label-hardware-address");
		gtk_label_set_text (GTK_LABEL (label), str);
		g_free (str);
	}

	return TRUE;
}

static void
nma_show_info_cb (GtkMenuItem *mi, NMApplet *applet)
{
	GtkWidget *info_dialog;

	info_dialog = glade_xml_get_widget (applet->info_dialog_xml, "info_dialog");

	if (nma_update_info (applet)) {
		gtk_window_present (GTK_WINDOW (info_dialog));
		g_signal_connect_swapped (info_dialog, "response", G_CALLBACK (gtk_widget_hide), info_dialog);
	}
}

static void about_dialog_activate_link_cb (GtkAboutDialog *about,
                                           const gchar *url,
                                           gpointer data)
{
	GError *error = NULL;
	gboolean ret;
	char *cmdline;
	GdkScreen *gscreen;
	GtkWidget *error_dialog;

	gscreen = gdk_screen_get_default();

	cmdline = g_strconcat ("gnome-open ", url, NULL);
	ret = gdk_spawn_command_line_on_screen (gscreen, cmdline, &error);
	g_free (cmdline);

	if (ret == TRUE)
		return;

	g_error_free (error);
	error = NULL;

	cmdline = g_strconcat ("xdg-open ", url, NULL);
	ret = gdk_spawn_command_line_on_screen (gscreen, cmdline, &error);
	g_free (cmdline);
	
	if (ret == FALSE) {
		error_dialog = gtk_message_dialog_new ( NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "Failed to show url %s", error->message); 
		gtk_dialog_run (GTK_DIALOG (error_dialog));
		g_error_free (error);
	}

}

static void nma_about_cb (GtkMenuItem *mi, NMApplet *applet)
{
	static const gchar *authors[] =
	{
		"The Red Hat Desktop Team, including:\n",
		"Christopher Aillon <caillon@redhat.com>",
		"Jonathan Blandford <jrb@redhat.com>",
		"John Palmieri <johnp@redhat.com>",
		"Ray Strode <rstrode@redhat.com>",
		"Colin Walters <walters@redhat.com>",
		"Dan Williams <dcbw@redhat.com>",
		"David Zeuthen <davidz@redhat.com>",
		"\nAnd others, including:\n",
		"Bill Moss <bmoss@clemson.edu>",
		"Tom Parker",
		"j@bootlab.org",
		"Peter Jones <pjones@redhat.com>",
		"Robert Love <rml@novell.com>",
		"Tim Niemueller <tim@niemueller.de>",
		NULL
	};

	static const gchar *artists[] =
	{
		"Diana Fong <dfong@redhat.com>",
		NULL
	};


	/* FIXME: unnecessary with libgnomeui >= 2.16.0 */
	static gboolean been_here = FALSE;
	if (!been_here)
	{
		been_here = TRUE;
		gtk_about_dialog_set_url_hook (about_dialog_activate_link_cb, NULL, NULL);
	}

	/* GTK 2.6 and later code */
	gtk_show_about_dialog (NULL,
	                       "name", _("NetworkManager Applet"),
	                       "version", VERSION,
	                       "copyright", _("Copyright \xc2\xa9 2004-2007 Red Hat, Inc.\n"
					                  "Copyright \xc2\xa9 2005-2007 Novell, Inc."),
	                       "comments", _("Notification area applet for managing your network devices and connections."),
	                       "website", "http://www.gnome.org/projects/NetworkManager/",
	                       "authors", authors,
	                       "artists", artists,
	                       "translator-credits", _("translator-credits"),
	                       "logo-icon-name", GTK_STOCK_NETWORK,
	                       NULL);
}


/*
 * show_warning_dialog
 *
 * pop up a warning or error dialog with certain text
 *
 */
static gboolean show_warning_dialog (char *mesg)
{
	GtkWidget	*	dialog;

	dialog = gtk_message_dialog_new (NULL, 0, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, mesg, NULL);

	/* Bash focus-stealing prevention in the face */
	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER_ALWAYS);
	gtk_widget_realize (dialog);
	gdk_x11_window_set_user_time (dialog->window, gtk_get_current_event_time ());
	gtk_window_present (GTK_WINDOW (dialog));

	g_signal_connect_swapped (dialog, "response", G_CALLBACK (gtk_widget_destroy), dialog);
	g_free (mesg);

	return FALSE;
}


/*
 * nma_schedule_warning_dialog
 *
 * Run a warning dialog in the main event loop.
 *
 */
void nma_schedule_warning_dialog (NMApplet *applet, const char *msg)
{
	char *lcl_msg;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (msg != NULL);

	lcl_msg = g_strdup (msg);
	g_idle_add ((GSourceFunc) show_warning_dialog, lcl_msg);
}


typedef struct {
	NMApplet *applet;
	NMDevice *device;
	NMAccessPoint *ap;
} DeviceMenuItemInfo;

static void
device_menu_item_info_destroy (gpointer data)
{
	g_slice_free (DeviceMenuItemInfo, data);
}

/*
 * nma_menu_item_activate
 *
 * Signal function called when user clicks on a menu item
 *
 */
static void
nma_menu_item_activate (GtkMenuItem *item, gpointer user_data)
{
	DeviceMenuItemInfo *info = (DeviceMenuItemInfo *) user_data;
	NMSetting *setting = NULL;
	char *specific_object = "/";

	// FIXME: find & use an existing connection that may apply
	// to the device/ap being activated here

	if (NM_IS_DEVICE_802_3_ETHERNET (info->device)) {
		setting = nm_setting_wired_new ();
		specific_object = NULL;
	} else if (NM_IS_DEVICE_802_11_WIRELESS (info->device)) {
		NMSettingWireless *wireless;
		const GByteArray *ap_ssid;

		setting = nm_setting_wireless_new ();
		wireless = (NMSettingWireless *) setting;

		// FIXME: have some sort of NMSettingWireless and
		// NMSettingWirelessSecurity constructors that take an NMAccessPoint
		// as input and spit out compatible Settings

		ap_ssid = nm_access_point_get_ssid (info->ap);
		wireless->ssid = g_byte_array_sized_new (ap_ssid->len);
		g_byte_array_append (wireless->ssid, ap_ssid->data, ap_ssid->len);

		wireless->mode = g_strdup ("infrastructure");

		specific_object = (char *) nm_object_get_path (NM_OBJECT (info->ap));
	} else
		g_warning ("Unhandled device type '%s'", G_OBJECT_CLASS_NAME (info->device));

	if (setting) {
		AppletDbusConnectionSettings *exported_con;
		NMConnection *connection;
		NMSettingConnection *s_con;

		connection = nm_connection_new ();
		nm_connection_add_setting (connection, setting);

		s_con = (NMSettingConnection *) nm_setting_connection_new ();
		s_con->name = g_strdup ("Auto");
		s_con->devtype = g_strdup (setting->name);
		s_con->autoconnect = FALSE;
		nm_connection_add_setting (connection, (NMSetting *) s_con);

		exported_con = applet_dbus_settings_add_connection (APPLET_DBUS_SETTINGS (info->applet->settings),
		                                                    connection);
		if (exported_con) {
			nm_device_activate (info->device,
			                    NM_DBUS_SERVICE_USER_SETTINGS,
			                    nm_connection_settings_get_dbus_object_path (NM_CONNECTION_SETTINGS (exported_con)),
			                    (const char *) specific_object);
		} else {
			nm_warning ("Couldn't create default connection.");
		}
	}

//	nmi_dbus_signal_user_interface_activated (info->applet->connection);
}

static gboolean
vpn_animation_timeout (gpointer data)
{
	NMApplet *applet = NM_APPLET (data);

	foo_set_icon (applet, applet->vpn_connecting_icons[applet->animation_step], ICON_LAYER_VPN);

	applet->animation_step++;
	if (applet->animation_step >= NUM_VPN_CONNECTING_FRAMES)
		applet->animation_step = 0;

	return TRUE;
}

static void
vpn_connection_state_changed (NMVPNConnection *connection, NMVPNConnectionState state, gpointer user_data)
{
	NMApplet *applet = NM_APPLET (user_data);
	VPNConnectionInfo *info;

	info = (VPNConnectionInfo *) g_object_get_data (G_OBJECT (connection), "vpn-info");

	switch (state) {
	case NM_VPN_CONNECTION_STATE_ACTIVATED:
		if (applet->animation_id) {
			g_source_remove (applet->animation_id);
			applet->animation_id = 0;
		}
		foo_set_icon (applet, applet->vpn_lock_icon, ICON_LAYER_VPN);
		vpn_connection_info_set_last_attempt_success (info, TRUE);
		break;
	case NM_VPN_CONNECTION_STATE_PREPARE:
	case NM_VPN_CONNECTION_STATE_CONNECT:
	case NM_VPN_CONNECTION_STATE_IP_CONFIG_GET:
		if (applet->animation_id == 0) {
			applet->animation_step = 0;
			applet->animation_id = g_timeout_add (100, vpn_animation_timeout, applet);
		}
		break;
	case NM_VPN_CONNECTION_STATE_FAILED:
		vpn_connection_info_set_last_attempt_success (info, FALSE);
		/* Fall through */
	case NM_VPN_CONNECTION_STATE_DISCONNECTED:
		g_hash_table_remove (applet->vpn_connections, nm_vpn_connection_get_name (connection));
		/* Fall through */
	default:
		if (applet->animation_id) {
			g_source_remove (applet->animation_id);
			applet->animation_id = 0;
		}
		foo_set_icon (applet, NULL, ICON_LAYER_VPN);
		break;
	}
}


static void
nma_menu_vpn_item_clicked (GtkMenuItem *item, gpointer user_data)
{
	NMApplet *applet = NM_APPLET (user_data);
	VPNConnectionInfo *info;
	NMVPNConnection *connection;

	info = (VPNConnectionInfo *) g_object_get_data (G_OBJECT (item), "vpn");
	g_assert (info);

	connection = g_hash_table_lookup (applet->vpn_connections, vpn_connection_info_get_name (info));

	if (connection) {
		/* Connection is active, disconnect */
		nm_vpn_connection_disconnect (connection);
	} else {
		/* Connection inactive, activate */
		GHashTable *properties;

		properties = vpn_connection_info_get_properties (info);

		/* Get passwords */
		if (nma_vpn_request_password (vpn_connection_info_get_name (info),
								vpn_connection_info_get_service (info),
								vpn_connection_info_get_last_attempt_success (info) == FALSE,
								properties)) {
			NMDevice *device;

			device = get_first_active_device (applet);

			connection = nm_vpn_manager_connect (applet->vpn_manager,
										  vpn_connection_info_get_service (info),
										  vpn_connection_info_get_name (info),
										  properties,
										  device,
										  vpn_connection_info_get_routes (info));
		}

		if (connection) {
			g_object_set_data_full (G_OBJECT (connection), "vpn-info", vpn_connection_info_copy (info),
							    (GDestroyNotify) vpn_connection_info_destroy);

			g_signal_connect (connection, "state-changed",
						   G_CALLBACK (vpn_connection_state_changed),
						   applet);

			g_hash_table_insert (applet->vpn_connections,
							 g_strdup (vpn_connection_info_get_name (info)),
							 connection);
		} else {
			/* FIXME: show a dialog or something */
			g_warning ("Can't connect");
		}
	}
		
//	nmi_dbus_signal_user_interface_activated (applet->connection);
}


/*
 * nma_menu_configure_vpn_item_activate
 *
 * Signal function called when user clicks "Configure VPN..."
 *
 */
static void
nma_menu_configure_vpn_item_activate (GtkMenuItem *item, gpointer user_data)
{
	NMApplet	*applet = (NMApplet *)user_data;
	const char *argv[] = { BINDIR "/nm-vpn-properties", NULL};

	g_spawn_async (NULL, (gchar **) argv, NULL, 0, NULL, NULL, NULL, NULL);

//	nmi_dbus_signal_user_interface_activated (applet->connection);
}


/*
 * nma_menu_add_separator_item
 *
 */
static void
nma_menu_add_separator_item (GtkMenuShell *menu)
{
	GtkWidget *menu_item;

	menu_item = gtk_separator_menu_item_new ();
	gtk_menu_shell_append (menu, menu_item);
	gtk_widget_show (menu_item);
}


/*
 * nma_menu_add_text_item
 *
 * Add a non-clickable text item to a menu
 *
 */
static void nma_menu_add_text_item (GtkWidget *menu, char *text)
{
	GtkWidget		*menu_item;

	g_return_if_fail (text != NULL);
	g_return_if_fail (menu != NULL);

	menu_item = gtk_menu_item_new_with_label (text);
	gtk_widget_set_sensitive (menu_item, FALSE);

	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);
	gtk_widget_show (menu_item);
}


/*
 * nma_menu_add_device_item
 *
 * Add a network device to the menu
 *
 */
static void
nma_menu_add_device_item (GtkWidget *menu,
					 NMDevice *device,
					 gint n_devices,
					 NMApplet *applet)
{
	GtkMenuItem *menu_item = NULL;

	if (NM_IS_DEVICE_802_11_WIRELESS (device))
		menu_item = wireless_menu_item_new (NM_DEVICE_802_11_WIRELESS (device), n_devices);
	else if (NM_IS_DEVICE_802_3_ETHERNET (device))
		menu_item = wired_menu_item_new (NM_DEVICE_802_3_ETHERNET (device), n_devices);
	else
		g_warning ("Unhandled device type %s", G_OBJECT_CLASS_NAME (device));

	if (menu_item) {
		DeviceMenuItemInfo *info;

		info = g_slice_new (DeviceMenuItemInfo);
		info->applet = applet;
		info->device = device;
		info->ap = NULL;

		g_signal_connect_data (menu_item, "activate",
						   G_CALLBACK (nma_menu_item_activate),
						   info,
						   (GClosureNotify) device_menu_item_info_destroy, 0);

		gtk_menu_shell_append (GTK_MENU_SHELL (menu), GTK_WIDGET (menu_item));
		gtk_widget_show (GTK_WIDGET (menu_item));
	}
}


static void custom_essid_item_selected (GtkWidget *menu_item, NMApplet *applet)
{
}


static void nma_menu_add_custom_essid_item (GtkWidget *menu, NMApplet *applet)
{
	GtkWidget *menu_item;
	GtkWidget *label;

	menu_item = gtk_menu_item_new ();
	label = gtk_label_new_with_mnemonic (_("_Connect to Other Wireless Network..."));
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	gtk_container_add (GTK_CONTAINER (menu_item), label);
	gtk_widget_show_all (menu_item);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);
	g_signal_connect (menu_item, "activate", G_CALLBACK (custom_essid_item_selected), applet);
}


static void new_network_item_selected (GtkWidget *menu_item, NMApplet *applet)
{
}


static void
nma_menu_add_create_network_item (GtkWidget *menu, NMApplet *applet)
{
	GtkWidget *menu_item;
	GtkWidget *label;

	menu_item = gtk_menu_item_new ();
	label = gtk_label_new_with_mnemonic (_("Create _New Wireless Network..."));
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	gtk_container_add (GTK_CONTAINER (menu_item), label);
	gtk_widget_show_all (menu_item);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);
	g_signal_connect (menu_item, "activate", G_CALLBACK (new_network_item_selected), applet);
}


typedef struct {
	NMApplet *	applet;
	NMDevice * device;
	const GByteArray * active_ssid;
	GtkWidget * menu;
} AddNetworksCB;

#define AP_HASH_LEN 16

static char *
ap_hash (NMAccessPoint * ap)
{
	struct GnomeKeyringMD5Context ctx;
	unsigned char * digest = NULL;
	unsigned char md5_data[66];
	unsigned char input[33];
	const GByteArray * ssid;
	int mode;
	guint32 flags, wpa_flags, rsn_flags;

	g_return_val_if_fail (ap, NULL);

	mode = nm_access_point_get_mode (ap);
	flags = nm_access_point_get_flags (ap);
	wpa_flags = nm_access_point_get_wpa_flags (ap);
	rsn_flags = nm_access_point_get_rsn_flags (ap);

	memset (&input[0], 0, sizeof (input));

	ssid = nm_access_point_get_ssid (ap);
	if (ssid)
		memcpy (input, ssid->data, ssid->len);

	if (mode == IW_MODE_INFRA)
		input[32] |= (1 << 0);
	else if (mode == IW_MODE_ADHOC)
		input[32] |= (1 << 1);
	else
		input[32] |= (1 << 2);

	/* Separate out no encryption, WEP-only, and WPA-capable */
	if (  !(flags & NM_802_11_AP_FLAGS_PRIVACY)
	    && (wpa_flags == NM_802_11_AP_SEC_NONE)
	    && (rsn_flags == NM_802_11_AP_SEC_NONE))
		input[32] |= (1 << 3);
	else if (   (flags & NM_802_11_AP_FLAGS_PRIVACY)
	         && (wpa_flags == NM_802_11_AP_SEC_NONE)
	         && (rsn_flags == NM_802_11_AP_SEC_NONE))
		input[32] |= (1 << 4);
	else if (   !(flags & NM_802_11_AP_FLAGS_PRIVACY)
	         &&  (wpa_flags != NM_802_11_AP_SEC_NONE)
	         &&  (rsn_flags != NM_802_11_AP_SEC_NONE))
		input[32] |= (1 << 5);
	else
		input[32] |= (1 << 6);

	digest = g_malloc (sizeof (unsigned char) * AP_HASH_LEN);
	if (digest == NULL)
		goto out;

	gnome_keyring_md5_init (&ctx);
	memcpy (md5_data, input, sizeof (input));
	memcpy (&md5_data[33], input, sizeof (input));
	gnome_keyring_md5_update (&ctx, md5_data, sizeof (md5_data));
	gnome_keyring_md5_final (digest, &ctx);

out:
	return digest;
}

struct dup_data {
	GtkWidget * found;
	guchar * hash;
};

static void
find_duplicate (GtkWidget * widget,
                gpointer user_data)
{
	struct dup_data * data = (struct dup_data *) user_data;
	const guchar * hash;
	guint32 hash_len = 0;

	g_return_if_fail (data);
	g_return_if_fail (data->hash);

	if (data->found || !NM_IS_NETWORK_MENU_ITEM (widget))
		return;

	hash = nm_network_menu_item_get_hash (NM_NETWORK_MENU_ITEM (widget),
	                                      &hash_len);
	if (hash == NULL || hash_len != AP_HASH_LEN)
		return;

	if (memcmp (hash, data->hash, AP_HASH_LEN) == 0)
		data->found = widget;
}

/*
 * nma_add_networks_helper
 *
 */
static void
nma_add_networks_helper (gpointer data, gpointer user_data)
{
	NMAccessPoint *ap = NM_ACCESS_POINT (data);
	AddNetworksCB *cb_data = (AddNetworksCB *) user_data;
	const GByteArray * ssid;
	gint8 strength;
	struct dup_data dup_data = { NULL, NULL };

	/* Don't add BSSs that hide their SSID */
	ssid = nm_access_point_get_ssid (ap);
	if (!ssid || nma_is_empty_ssid (ssid->data, ssid->len))
		goto out;

	strength = nm_access_point_get_strength (ap);

	dup_data.found = NULL;
	dup_data.hash = ap_hash (ap);
	if (!dup_data.hash)
		goto out;
	gtk_container_foreach (GTK_CONTAINER (cb_data->menu),
	                       find_duplicate,
	                       &dup_data);

	if (dup_data.found) {
		/* Just update strength if greater than what's there */
		if (nm_network_menu_item_get_strength (NM_NETWORK_MENU_ITEM (dup_data.found)) > strength)
			nm_network_menu_item_set_strength (NM_NETWORK_MENU_ITEM (dup_data.found), strength);
	} else {
		GtkWidget * item;
		DeviceMenuItemInfo *info;

		item = nm_network_menu_item_new (cb_data->applet->encryption_size_group,
		                                 dup_data.hash, AP_HASH_LEN);
		nm_network_menu_item_set_ssid (NM_NETWORK_MENU_ITEM (item), ssid);
		nm_network_menu_item_set_strength (NM_NETWORK_MENU_ITEM (item), strength);
		nm_network_menu_item_set_detail (NM_NETWORK_MENU_ITEM (item),
		                                 ap, cb_data->applet->adhoc_icon);

		gtk_menu_shell_append (GTK_MENU_SHELL (cb_data->menu), item);

		if ((nm_device_get_state (cb_data->device) == NM_DEVICE_STATE_ACTIVATED)
		    && cb_data->active_ssid) {
			if (ssid && nma_same_ssid (ssid, cb_data->active_ssid))
				gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (item), TRUE);
		}

		info = g_slice_new (DeviceMenuItemInfo);
		info->applet = cb_data->applet;
		info->device = cb_data->device;
		info->ap = ap;

		g_signal_connect_data (item, "activate",
						   G_CALLBACK (nma_menu_item_activate),
						   info,
						   (GClosureNotify) device_menu_item_info_destroy, 0);

		gtk_widget_show_all (item);
	}

out:
	g_free (dup_data.hash);
}


/*
 * nma_has_encrypted_networks_helper
 *
 */
static void
nma_has_encrypted_networks_helper (gpointer data, gpointer user_data)
{
	NMAccessPoint *ap = NM_ACCESS_POINT (data);
	gboolean *has_encrypted = user_data;
	guint32 flags, wpa_flags, rsn_flags;

	flags = nm_access_point_get_flags (ap);
	wpa_flags = nm_access_point_get_wpa_flags (ap);
	rsn_flags = nm_access_point_get_rsn_flags (ap);

	if (   (flags & NM_802_11_AP_FLAGS_PRIVACY)
	    || (wpa_flags != NM_802_11_AP_SEC_NONE)
	    || (rsn_flags != NM_802_11_AP_SEC_NONE))
		*has_encrypted = TRUE;
}


static gint
sort_wireless_networks (gconstpointer tmpa,
                        gconstpointer tmpb)
{
	NMAccessPoint * a = NM_ACCESS_POINT (tmpa);
	NMAccessPoint * b = NM_ACCESS_POINT (tmpb);
	const GByteArray * a_ssid;
	const GByteArray * b_ssid;
	int a_mode, b_mode, i;

	if (a && !b)
		return 1;
	if (b && !a)
		return -1;

	a_ssid = nm_access_point_get_ssid (a);
	b_ssid = nm_access_point_get_ssid (b);

	if (a_ssid && !b_ssid)
		return 1;
	if (b_ssid && !a_ssid)
		return -1;

	if (a_ssid && b_ssid) {
		/* Can't use string compares because SSIDs are byte arrays and
		 * may legally contain embedded NULLs.
		 */
		for (i = 0; i < MIN(a_ssid->len, b_ssid->len); i++) {
			if (tolower(a_ssid->data[i]) > tolower(b_ssid->data[i]))
				return 1;
			else if (tolower(b_ssid->data[i]) > tolower(a_ssid->data[i]))
				return -1;
		}

		if (a_ssid->len > b_ssid->len)
			return 1;
		if (b_ssid->len > a_ssid->len)
			return -1;
	}

	a_mode = nm_access_point_get_mode (a);
	b_mode = nm_access_point_get_mode (b);
	if (a_mode != b_mode) {
		if (a_mode == IW_MODE_INFRA)
			return 1;
		return -1;
	}

	return 0;
}

/*
 * nma_menu_device_add_networks
 *
 */
static void
nma_menu_device_add_networks (GtkWidget *menu, NMDevice *device, NMApplet *applet)
{
	GSList *networks;
	AddNetworksCB add_networks_cb;

	if (!NM_IS_DEVICE_802_11_WIRELESS (device) || !nm_client_wireless_get_enabled (applet->nm_client))
		return;

	networks = nm_device_802_11_wireless_get_networks (NM_DEVICE_802_11_WIRELESS (device));

	add_networks_cb.applet = applet;
	add_networks_cb.device = device;
	add_networks_cb.active_ssid = NULL;
	add_networks_cb.menu = menu;

	if (nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED) {
		NMAccessPoint *ap;

		ap = nm_device_802_11_wireless_get_active_network (NM_DEVICE_802_11_WIRELESS (device));
		if (ap)
			add_networks_cb.active_ssid = nm_access_point_get_ssid (ap);
	}

	/* Add all networks in our network list to the menu */
	networks = g_slist_sort (networks, sort_wireless_networks);
	g_slist_foreach (networks, nma_add_networks_helper, &add_networks_cb);
	g_slist_free (networks);
}

static gint
sort_devices (gconstpointer a, gconstpointer b)
{
	NMDevice *aa = NM_DEVICE (a);
	NMDevice *bb = NM_DEVICE (b);
	GType aa_type;
	GType bb_type;

	aa_type = G_OBJECT_TYPE (G_OBJECT (aa));
	bb_type = G_OBJECT_TYPE (G_OBJECT (bb));

	if (aa_type == bb_type) {
		char *aa_desc = nm_device_get_description (aa);
		char *bb_desc = nm_device_get_description (bb);
		gint ret;

		ret = strcmp (aa_desc, bb_desc);

		g_free (aa_desc);
		g_free (bb_desc);

		return ret;
	}

	if (aa_type == NM_TYPE_DEVICE_802_3_ETHERNET && bb_type == NM_TYPE_DEVICE_802_11_WIRELESS)
		return -1;
	if (aa_type == NM_TYPE_DEVICE_802_11_WIRELESS && bb_type == NM_TYPE_DEVICE_802_3_ETHERNET)
		return 1;

	return 0;
}

static void
nma_menu_add_devices (GtkWidget *menu, NMApplet *applet)
{
	GSList *devices = NULL;
	GSList *iter;
	gint n_wireless_interfaces = 0;
	gint n_wired_interfaces = 0;

	devices = nm_client_get_devices (applet->nm_client);

	if (devices)
		devices = g_slist_sort (devices, sort_devices);

	for (iter = devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);

		/* Ignore unsupported devices */
		if (!(nm_device_get_capabilities (device) & NM_DEVICE_CAP_NM_SUPPORTED))
			continue;

		if (NM_IS_DEVICE_802_11_WIRELESS (device)) {
			if (nm_client_wireless_get_enabled (applet->nm_client))
				n_wireless_interfaces++;
		} else if (NM_IS_DEVICE_802_3_ETHERNET (device))
			n_wired_interfaces++;
	}

	if (n_wired_interfaces == 0 && n_wireless_interfaces == 0) {
		nma_menu_add_text_item (menu, _("No network devices have been found"));
		goto out;
	}

	/* Add all devices in our device list to the menu */
	for (iter = devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);
		gint n_devices = 0;

		/* Ignore unsupported devices */
		if (!(nm_device_get_capabilities (device) & NM_DEVICE_CAP_NM_SUPPORTED))
			continue;

		if (NM_IS_DEVICE_802_11_WIRELESS (device))
			n_devices = n_wireless_interfaces;
		else if (NM_IS_DEVICE_802_3_ETHERNET (device))
			n_devices = n_wired_interfaces++;

		nma_menu_add_device_item (menu, device, n_devices, applet);
		nma_menu_device_add_networks (menu, device, applet);
	}

	if (n_wireless_interfaces > 0 && nm_client_wireless_get_enabled (applet->nm_client)) {
		/* Add the "Other wireless network..." entry */
		nma_menu_add_separator_item (GTK_MENU_SHELL (menu));
		nma_menu_add_custom_essid_item (menu, applet);
		nma_menu_add_create_network_item (menu, applet);
	}

 out:
	g_slist_free (devices);
}

static int
sort_vpn_connections (gconstpointer a, gconstpointer b)
{
	VPNConnectionInfo *aa = (VPNConnectionInfo *) a;
	VPNConnectionInfo *bb = (VPNConnectionInfo *) b;

	return strcmp (vpn_connection_info_get_name (aa), vpn_connection_info_get_name (bb));
}

static void
nma_menu_add_vpn_submenu (GtkWidget *menu, NMApplet *applet)
{
	GtkMenu *vpn_menu;
	GtkMenuItem *item;
	GSList *list;
	GSList *iter;

	nma_menu_add_separator_item (GTK_MENU_SHELL (menu));

	vpn_menu = GTK_MENU (gtk_menu_new ());

	item = GTK_MENU_ITEM (gtk_menu_item_new_with_mnemonic (_("_VPN Connections")));
	gtk_menu_item_set_submenu (item, GTK_WIDGET (vpn_menu));
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), GTK_WIDGET (item));

	list = vpn_connection_info_list ();
	list = g_slist_sort (list, sort_vpn_connections);

	for (iter = list; iter; iter = iter->next) {
		VPNConnectionInfo *info = (VPNConnectionInfo *) iter->data;

		item = GTK_MENU_ITEM (gtk_check_menu_item_new_with_label (vpn_connection_info_get_name (info)));
		if (g_hash_table_lookup (applet->vpn_connections, vpn_connection_info_get_name (info)))
			gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (item), TRUE);

		g_object_set_data_full (G_OBJECT (item), "vpn", info, 
						    (GDestroyNotify) vpn_connection_info_destroy);

		if (nm_client_get_state (applet->nm_client) != NM_STATE_CONNECTED)
			gtk_widget_set_sensitive (GTK_WIDGET (item), FALSE);

		g_signal_connect (item, "activate", G_CALLBACK (nma_menu_vpn_item_clicked), applet);
		gtk_menu_shell_append (GTK_MENU_SHELL (vpn_menu), GTK_WIDGET (item));
	}

	/* Draw a seperator, but only if we have VPN connections above it */
	if (list)
		nma_menu_add_separator_item (GTK_MENU_SHELL (vpn_menu));

	item = GTK_MENU_ITEM (gtk_menu_item_new_with_mnemonic (_("_Configure VPN...")));
	g_signal_connect (item, "activate", G_CALLBACK (nma_menu_configure_vpn_item_activate), applet);
	gtk_menu_shell_append (GTK_MENU_SHELL (vpn_menu), GTK_WIDGET (item));
}


static void
nma_set_wireless_enabled_cb (GtkWidget *widget, NMApplet *applet)
{
	gboolean state;

	g_return_if_fail (applet != NULL);

	state = gtk_check_menu_item_get_active (GTK_CHECK_MENU_ITEM (widget));
	nm_client_wireless_set_enabled (applet->nm_client, state);
}


static void
nma_set_networking_enabled_cb (GtkWidget *widget, NMApplet *applet)
{
	gboolean state;

	g_return_if_fail (applet != NULL);

	state = gtk_check_menu_item_get_active (GTK_CHECK_MENU_ITEM (widget));
	nm_client_sleep (applet->nm_client, !state);
}

/*
 * nma_menu_clear
 *
 * Destroy the menu and each of its items data tags
 *
 */
static void nma_menu_clear (NMApplet *applet)
{
	GList * children;

	g_return_if_fail (applet != NULL);

	if (applet->menu)
		gtk_widget_destroy (applet->menu);

	gtk_menu_item_remove_submenu (GTK_MENU_ITEM (applet->top_menu_item));
	applet->menu = nma_menu_create (GTK_MENU_ITEM (applet->top_menu_item), applet);
#ifndef HAVE_STATUS_ICON
	g_signal_connect (applet->menu, "deactivate", G_CALLBACK (nma_menu_deactivate_cb), applet);
#endif /* !HAVE_STATUS_ICON */
}


/*
 * nma_menu_show_cb
 *
 * Pop up the wireless networks menu
 *
 */
static void nma_menu_show_cb (GtkWidget *menu, NMApplet *applet)
{
	g_return_if_fail (menu != NULL);
	g_return_if_fail (applet != NULL);
	g_return_if_fail (applet->menu != NULL);

#ifdef HAVE_STATUS_ICON
	gtk_status_icon_set_tooltip (applet->status_icon, NULL);
#else
	gtk_tooltips_set_tip (applet->tooltips, applet->event_box, NULL, NULL);
#endif /* HAVE_STATUS_ICON */

	if (!nm_client_manager_is_running (applet->nm_client)) {
		nma_menu_add_text_item (menu, _("NetworkManager is not running..."));
		return;
	}

	if (nm_client_get_state (applet->nm_client) == NM_STATE_ASLEEP) {
		nma_menu_add_text_item (menu, _("Networking disabled"));
		return;
	}

	nma_menu_add_devices (menu, applet);
	nma_menu_add_vpn_submenu (menu, applet);

	gtk_widget_show_all (applet->menu);

//	nmi_dbus_signal_user_interface_activated (applet->connection);
}

/*
 * nma_menu_create
 *
 * Create the applet's dropdown menu
 *
 */
static GtkWidget *
nma_menu_create (GtkMenuItem *parent, NMApplet *applet)
{
	GtkWidget	*menu;

	g_return_val_if_fail (parent != NULL, NULL);
	g_return_val_if_fail (applet != NULL, NULL);

	menu = gtk_menu_new ();
	gtk_container_set_border_width (GTK_CONTAINER (menu), 0);
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (parent), menu);
	g_signal_connect (menu, "show", G_CALLBACK (nma_menu_show_cb), applet);

	return menu;
}


/*
 * nma_context_menu_update
 *
 */
static void
nma_context_menu_update (NMApplet *applet)
{
	NMState state;
	gboolean have_wireless = FALSE;

	state = nm_client_get_state (applet->nm_client);

	gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (applet->enable_networking_item),
							  state != NM_STATE_ASLEEP);

	gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (applet->stop_wireless_item),
							  nm_client_wireless_get_enabled (applet->nm_client));

	gtk_widget_set_sensitive (applet->info_menu_item,
						 state == NM_STATE_CONNECTED);

	if (state != NM_STATE_ASLEEP) {
		GSList *list;
		GSList *iter;
	
		list = nm_client_get_devices (applet->nm_client);
		for (iter = list; iter; iter = iter->next) {
			if (NM_IS_DEVICE_802_11_WIRELESS (iter->data)) {
				have_wireless = TRUE;
				break;
			}
		}
		g_slist_free (list);
	}

	if (have_wireless)
		gtk_widget_show_all (applet->stop_wireless_item);
	else
		gtk_widget_hide (applet->stop_wireless_item);
}

/*
 * nma_context_menu_create
 *
 * Generate the contextual popup menu.
 *
 */
static GtkWidget *nma_context_menu_create (NMApplet *applet)
{
	GtkMenuShell *menu;
	GtkWidget	*menu_item;
	GtkWidget *image;

	g_return_val_if_fail (applet != NULL, NULL);

	menu = GTK_MENU_SHELL (gtk_menu_new ());

	/* 'Enable Networking' item */
	applet->enable_networking_item = gtk_check_menu_item_new_with_mnemonic (_("Enable _Networking"));
	g_signal_connect (applet->enable_networking_item,
				   "toggled",
				   G_CALLBACK (nma_set_networking_enabled_cb),
				   applet);
	gtk_menu_shell_append (menu, applet->enable_networking_item);

	/* 'Enable Wireless' item */
	applet->stop_wireless_item = gtk_check_menu_item_new_with_mnemonic (_("Enable _Wireless"));
	g_signal_connect (applet->stop_wireless_item,
				   "toggled",
				   G_CALLBACK (nma_set_wireless_enabled_cb),
				   applet);
	gtk_menu_shell_append (menu, applet->stop_wireless_item);

	/* 'Connection Information' item */
	applet->info_menu_item = gtk_image_menu_item_new_with_mnemonic (_("Connection _Information"));
	g_signal_connect (applet->info_menu_item,
				   "activate",
				   G_CALLBACK (nma_show_info_cb),
				   applet);
	image = gtk_image_new_from_stock (GTK_STOCK_INFO, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (applet->info_menu_item), image);
	gtk_menu_shell_append (menu, applet->info_menu_item);

	/* Separator */
	nma_menu_add_separator_item (menu);

#if 0	/* FIXME: Implement the help callback, nma_help_cb()! */
	/* Help item */
	menu_item = gtk_image_menu_item_new_with_mnemonic (_("_Help"));
	g_signal_connect (menu_item, "activate", G_CALLBACK (nma_help_cb), applet);
	image = gtk_image_new_from_stock (GTK_STOCK_HELP, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (menu_item), image);
	gtk_menu_shell_append (menu, menu_item);
	gtk_widget_set_sensitive (menu_item, FALSE);
#endif

	/* About item */
	menu_item = gtk_image_menu_item_new_with_mnemonic (_("_About"));
	g_signal_connect (menu_item, "activate", G_CALLBACK (nma_about_cb), applet);
	image = gtk_image_new_from_stock (GTK_STOCK_ABOUT, GTK_ICON_SIZE_MENU);
	gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (menu_item), image);
	gtk_menu_shell_append (menu, menu_item);

	gtk_widget_show_all (GTK_WIDGET (menu));

	return GTK_WIDGET (menu);
}


#ifdef HAVE_STATUS_ICON

/*
 * nma_status_icon_screen_changed_cb:
 *
 * Handle screen change events for the status icon
 *
 */
static void nma_status_icon_screen_changed_cb (GtkStatusIcon *icon, GParamSpec *pspec, NMApplet *applet)
{
	nma_icons_init (applet);
}

/*
 * nma_status_icon_size_changed_cb:
 *
 * Handle size change events for the status icon
 *
 */
static gboolean nma_status_icon_size_changed_cb (GtkStatusIcon *icon, gint size, NMApplet *applet)
{
	nma_icons_free (applet);

	applet->size = size;
	nma_icons_load_from_disk (applet);

	return TRUE;
}

/*
 * nma_status_icon_activate_cb:
 *
 * Handle left clicks for the status icon
 *
 */
static void nma_status_icon_activate_cb (GtkStatusIcon *icon, NMApplet *applet)
{
	nma_menu_clear (applet);
	gtk_menu_popup (GTK_MENU (applet->menu), NULL, NULL,
			gtk_status_icon_position_menu, icon,
			1, gtk_get_current_event_time ());
}

static void nma_status_icon_popup_menu_cb (GtkStatusIcon *icon, guint button, guint32 activate_time, NMApplet *applet)
{
	nma_context_menu_update (applet);
	gtk_menu_popup (GTK_MENU (applet->context_menu), NULL, NULL,
			gtk_status_icon_position_menu, icon,
			button, activate_time);
}

/*
 * nma_status_icon_popup_menu_cb:
 *
 * Handle right clicks for the status icon
 *
 */

#else /* !HAVE_STATUS_ICON */

/*
 * nma_menu_position_func
 *
 * Position main dropdown menu, adapted from netapplet
 *
 */
static void nma_menu_position_func (GtkMenu *menu G_GNUC_UNUSED, int *x, int *y, gboolean *push_in, gpointer user_data)
{
	int screen_w, screen_h, button_x, button_y, panel_w, panel_h;
	GtkRequisition requisition;
	GdkScreen *screen;
	NMApplet *applet = (NMApplet *)user_data;

	screen = gtk_widget_get_screen (applet->event_box);
	screen_w = gdk_screen_get_width (screen);
	screen_h = gdk_screen_get_height (screen);

	gdk_window_get_origin (applet->event_box->window, &button_x, &button_y);
	gtk_window_get_size (GTK_WINDOW (gtk_widget_get_toplevel (applet->event_box)), &panel_w, &panel_h);

	*x = button_x;

	/* Check to see if we would be placing the menu off of the end of the screen. */
	gtk_widget_size_request (GTK_WIDGET (menu), &requisition);
	if (button_y + panel_h + requisition.height >= screen_h)
		*y = button_y - requisition.height;
	else
		*y = button_y + panel_h;

	*push_in = TRUE;
}

/*
 * nma_toplevel_menu_button_press_cb
 *
 * Handle left/right-clicks for the dropdown and context popup menus
 *
 */
static gboolean nma_toplevel_menu_button_press_cb (GtkWidget *widget, GdkEventButton *event, NMApplet *applet)
{
	g_return_val_if_fail (applet != NULL, FALSE);

	switch (event->button)
	{
		case 1:
			nma_menu_clear (applet);
			gtk_widget_set_state (applet->event_box, GTK_STATE_SELECTED);
			gtk_menu_popup (GTK_MENU (applet->menu), NULL, NULL, nma_menu_position_func, applet, event->button, event->time);
			return TRUE;
		case 3:
			nma_context_menu_update (applet);
			gtk_menu_popup (GTK_MENU (applet->context_menu), NULL, NULL, nma_menu_position_func, applet, event->button, event->time);
			return TRUE;
		default:
			g_signal_stop_emission_by_name (widget, "button_press_event");
			return FALSE;
	}

	return FALSE;
}


/*
 * nma_toplevel_menu_button_press_cb
 *
 * Handle left-unclick on the dropdown menu.
 *
 */
static void nma_menu_deactivate_cb (GtkWidget *menu, NMApplet *applet)
{

	g_return_if_fail (applet != NULL);

	gtk_widget_set_state (applet->event_box, GTK_STATE_NORMAL);
}

/*
 * nma_theme_change_cb
 *
 * Destroy the popdown menu when the theme changes
 *
 */
static void nma_theme_change_cb (NMApplet *applet)
{
	g_return_if_fail (applet != NULL);

	nma_menu_clear (applet);
	if (applet->top_menu_item) {
		gtk_menu_item_remove_submenu (GTK_MENU_ITEM (applet->top_menu_item));
		applet->menu = nma_menu_create (GTK_MENU_ITEM (applet->top_menu_item), applet);
		g_signal_connect (applet->menu, "deactivate", G_CALLBACK (nma_menu_deactivate_cb), applet);
	}
}
#endif /* HAVE_STATUS_ICON */

/*
 * nma_setup_widgets
 *
 * Intialize the applet's widgets and packing, create the initial
 * menu of networks.
 *
 */
static gboolean
nma_setup_widgets (NMApplet *applet)
{
	g_return_val_if_fail (NM_IS_APPLET (applet), FALSE);

#ifdef HAVE_STATUS_ICON
	applet->status_icon = gtk_status_icon_new ();
	if (!applet->status_icon)
		return FALSE;

	g_signal_connect (applet->status_icon, "notify::screen",
			  G_CALLBACK (nma_status_icon_screen_changed_cb), applet);
	g_signal_connect (applet->status_icon, "size-changed",
			  G_CALLBACK (nma_status_icon_size_changed_cb), applet);
	g_signal_connect (applet->status_icon, "activate",
			  G_CALLBACK (nma_status_icon_activate_cb), applet);
	g_signal_connect (applet->status_icon, "popup-menu",
			  G_CALLBACK (nma_status_icon_popup_menu_cb), applet);

#else
	applet->tray_icon = egg_tray_icon_new ("NetworkManager");
	if (!applet->tray_icon)
		return FALSE;

	g_object_ref (applet->tray_icon);
	gtk_object_sink (GTK_OBJECT (applet->tray_icon));

	/* Event box is the main applet widget */
	applet->event_box = gtk_event_box_new ();
	if (!applet->event_box)
		return FALSE;
	gtk_container_set_border_width (GTK_CONTAINER (applet->event_box), 0);
	g_signal_connect (applet->event_box, "button_press_event", G_CALLBACK (nma_toplevel_menu_button_press_cb), applet);

	applet->pixmap = gtk_image_new ();
	if (!applet->pixmap)
		return FALSE;
	gtk_container_add (GTK_CONTAINER (applet->event_box), applet->pixmap);
	gtk_container_add (GTK_CONTAINER (applet->tray_icon), applet->event_box);
 	gtk_widget_show_all (GTK_WIDGET (applet->tray_icon));
#endif /* HAVE_STATUS_ICON */

	applet->top_menu_item = gtk_menu_item_new ();
	if (!applet->top_menu_item)
		return FALSE;
	gtk_widget_set_name (applet->top_menu_item, "ToplevelMenu");
	gtk_container_set_border_width (GTK_CONTAINER (applet->top_menu_item), 0);

	applet->menu = nma_menu_create (GTK_MENU_ITEM (applet->top_menu_item), applet);
	if (!applet->menu)
		return FALSE;
#ifndef HAVE_STATUS_ICON
	g_signal_connect (applet->menu, "deactivate", G_CALLBACK (nma_menu_deactivate_cb), applet);
#endif /* !HAVE_STATUS_ICON */

	applet->context_menu = nma_context_menu_create (applet);
	if (!applet->context_menu)
		return FALSE;
	applet->encryption_size_group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);
	if (!applet->encryption_size_group)
		return FALSE;

	return TRUE;
}


/*
 * nma_gconf_info_notify_callback
 *
 * Callback from gconf when wireless key/values have changed.
 *
 */
static void nma_gconf_info_notify_callback (GConfClient *client, guint connection_id, GConfEntry *entry, gpointer user_data)
{
	NMApplet *	applet = (NMApplet *)user_data;
	const char *		key = NULL;

	g_return_if_fail (client != NULL);
	g_return_if_fail (entry != NULL);
	g_return_if_fail (applet != NULL);

	if ((key = gconf_entry_get_key (entry)))
	{
		int	net_path_len = strlen (GCONF_PATH_WIRELESS_NETWORKS) + 1;

		if (strncmp (GCONF_PATH_WIRELESS_NETWORKS"/", key, net_path_len) == 0)
		{
			char 	*network = g_strdup ((key + net_path_len));
			char		*slash_pos;
			char		*unescaped_network;

			/* If its a key under the network name, zero out the slash so we
			 * are left with only the network name.
			 */
			unescaped_network = gconf_unescape_key (network, strlen (network));
			if ((slash_pos = strchr (unescaped_network, '/')))
				*slash_pos = '\0';

//			nmi_dbus_signal_update_network (applet->connection, unescaped_network, NETWORK_TYPE_ALLOWED);
			g_free (unescaped_network);
			g_free (network);
		}
	}
}


/*****************************************************************************/

static void
foo_update_icon (NMApplet *applet)
{
	GdkPixbuf	*pixbuf;
	GtkRequisition requisition;
	int i;

	if (!applet->icon_layers[0]) {
		pixbuf = g_object_ref (applet->no_connection_icon);
	} else {
		pixbuf = gdk_pixbuf_copy (applet->icon_layers[0]);

		for (i = ICON_LAYER_LINK + 1; i <= ICON_LAYER_MAX; i++) {
			GdkPixbuf *top = applet->icon_layers[i];

			if (!top)
				continue;

			gdk_pixbuf_composite (top, pixbuf, 0, 0, gdk_pixbuf_get_width (top),
							  gdk_pixbuf_get_height (top),
							  0, 0, 1.0, 1.0,
							  GDK_INTERP_NEAREST, 255);
		}
	}

	gtk_status_icon_set_from_pixbuf (applet->status_icon, pixbuf);
	g_object_unref (pixbuf);

	/* Add some padding to the applet to ensure the
	 * highlight has some space.
	 */
/* 	gtk_widget_set_size_request (GTK_WIDGET (applet), -1, -1); */
/* 	gtk_widget_size_request (GTK_WIDGET (applet), &requisition); */
/* 	gtk_widget_set_size_request (GTK_WIDGET (applet), requisition.width + 6, requisition.height + 2); */
}

static void
foo_set_icon (NMApplet *applet, GdkPixbuf *pixbuf, guint32 layer)
{
	if (layer > ICON_LAYER_MAX) {
		g_warning ("Tried to icon to invalid layer %d", layer);
		return;
	}

	/* Ignore setting of the same icon as is already displayed */
	if (applet->icon_layers[layer] == pixbuf)
		return;

	if (applet->icon_layers[layer]) {
		g_object_unref (applet->icon_layers[layer]);
		applet->icon_layers[layer] = NULL;
	}

	if (pixbuf)
		applet->icon_layers[layer] = g_object_ref (pixbuf);

	foo_update_icon (applet);
}

/* Device independent code to set the status icon and tooltip */

typedef struct {
	NMApplet *applet;
	NMDeviceState state;
} FooAnimationTimeoutInfo;

static void
foo_animation_timeout_info_destroy (gpointer data)
{
	g_slice_free (FooAnimationTimeoutInfo, data);
}

static gboolean
foo_animation_timeout (gpointer data)
{
	FooAnimationTimeoutInfo *info = (FooAnimationTimeoutInfo *) data;
	NMApplet *applet = info->applet;
	int stage = -1;

	switch (info->state) {
	case NM_DEVICE_STATE_PREPARE:
		stage = 0;
		break;
	case NM_DEVICE_STATE_CONFIG:
		stage = 1;
		break;
	case NM_DEVICE_STATE_IP_CONFIG:
		stage = 2;
		break;
	default:
		break;
	}

	if (stage >= 0)
		foo_set_icon (applet,
				    applet->network_connecting_icons[stage][applet->animation_step],
				    ICON_LAYER_LINK);

	applet->animation_step++;
	if (applet->animation_step >= NUM_CONNECTING_FRAMES)
		applet->animation_step = 0;

	return TRUE;
}

static void
foo_common_state_change (NMDevice *device, NMDeviceState state, NMApplet *applet)
{
	FooAnimationTimeoutInfo *info;

	switch (state) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_IP_CONFIG:
		info = g_slice_new (FooAnimationTimeoutInfo);
		info->applet = applet;
		info->state = state;
		applet->animation_step = 0;
		applet->animation_id = g_timeout_add_full (G_PRIORITY_DEFAULT_IDLE,
										   100, foo_animation_timeout,
										   info,
										   foo_animation_timeout_info_destroy);
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		break;
	default:
		break;
	}
}

/* Wireless device */

static void
foo_bssid_strength_changed (NMAccessPoint *ap, guint strength, gpointer user_data)
{
	NMApplet *applet = NM_APPLET (user_data);
	GdkPixbuf *pixbuf;
	const GByteArray * ssid;
	char *tip;

	strength = CLAMP (strength, 0, 100);

	if (strength > 80)
		pixbuf = applet->wireless_100_icon;
	else if (strength > 55)
		pixbuf = applet->wireless_75_icon;
	else if (strength > 30)
		pixbuf = applet->wireless_50_icon;
	else if (strength > 5)
		pixbuf = applet->wireless_25_icon;
	else
		pixbuf = applet->wireless_00_icon;

	foo_set_icon (applet, pixbuf, ICON_LAYER_LINK);

	ssid = nm_access_point_get_ssid (ap);
	tip = g_strdup_printf (_("Wireless network connection to '%s' (%d%%)"),
	                       ssid ? nma_escape_ssid (ssid->data, ssid->len) : "(none)",
	                       strength);

	gtk_status_icon_set_tooltip (applet->status_icon, tip);
	g_free (tip);
}

static gboolean
foo_wireless_state_change (NMDevice80211Wireless *device, NMDeviceState state, NMApplet *applet)
{
	char *iface;
	NMAccessPoint *ap = NULL;
	const GByteArray * ssid;
	char *tip = NULL;
	gboolean handled = FALSE;
	char * esc_ssid = "(none)";

	iface = nm_device_get_iface (NM_DEVICE (device));

	if (state == NM_DEVICE_STATE_PREPARE ||
	    state == NM_DEVICE_STATE_CONFIG ||
	    state == NM_DEVICE_STATE_IP_CONFIG ||
	    state == NM_DEVICE_STATE_NEED_AUTH ||
	    state == NM_DEVICE_STATE_ACTIVATED) {

		ap = nm_device_802_11_wireless_get_active_network (NM_DEVICE_802_11_WIRELESS (device));
		if (ap) {
			ssid = nm_access_point_get_ssid (ap);
			if (ssid)
				esc_ssid = (char *) nma_escape_ssid (ssid->data, ssid->len);
		}
	}

	switch (state) {
	case NM_DEVICE_STATE_PREPARE:
		tip = g_strdup_printf (_("Preparing device %s for the wireless network '%s'..."), iface, esc_ssid);
		break;
	case NM_DEVICE_STATE_CONFIG:
		tip = g_strdup_printf (_("Attempting to join the wireless network '%s'..."), esc_ssid);
		break;
	case NM_DEVICE_STATE_IP_CONFIG:
		tip = g_strdup_printf (_("Requesting a network address from the wireless network '%s'..."), esc_ssid);
		break;
	case NM_DEVICE_STATE_NEED_AUTH:
		tip = g_strdup_printf (_("Waiting for Network Key for the wireless network '%s'..."), esc_ssid);
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		applet->current_ap = ap;
		if (ap) {
			applet->wireless_strength_monitor = g_signal_connect (ap,
			                                                      "strength-changed",
			                                                      G_CALLBACK (foo_bssid_strength_changed),
			                                                      applet);
			foo_bssid_strength_changed (ap,
			                            nm_access_point_get_strength (ap),
			                            applet);
		}

#ifdef ENABLE_NOTIFY
		tip = g_strdup_printf (_("You are now connected to the wireless network '%s'."), esc_ssid);
		nma_send_event_notification (applet, NOTIFY_URGENCY_LOW, _("Connection Established"),
							    tip, "nm-device-wireless");
		g_free (tip);
#endif

		tip = g_strdup_printf (_("Wireless network connection to '%s'"), esc_ssid);

		handled = TRUE;
		break;
	case NM_DEVICE_STATE_DOWN:
	case NM_DEVICE_STATE_DISCONNECTED:
		if (applet->current_ap && applet->wireless_strength_monitor)
			g_signal_handler_disconnect (applet->current_ap, applet->wireless_strength_monitor);

		applet->current_ap = NULL;
		applet->wireless_strength_monitor = 0;
		break;
	default:
		break;
	}

	g_free (iface);

	if (tip) {
		gtk_status_icon_set_tooltip (applet->status_icon, tip);
		g_free (tip);
	}

	return handled;
}

/* Wired device */

static gboolean
foo_wired_state_change (NMDevice8023Ethernet *device, NMDeviceState state, NMApplet *applet)
{
	char *iface;
	char *tip = NULL;
	gboolean handled = FALSE;

	iface = nm_device_get_iface (NM_DEVICE (device));

	switch (state) {
	case NM_DEVICE_STATE_PREPARE:
		tip = g_strdup_printf (_("Preparing device %s for the wired network..."), iface);
		break;
	case NM_DEVICE_STATE_CONFIG:
		tip = g_strdup_printf (_("Configuring device %s for the wired network..."), iface);
		break;
	case NM_DEVICE_STATE_IP_CONFIG:
		tip = g_strdup_printf (_("Requesting a network address from the wired network..."));
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		foo_set_icon (applet, applet->wired_icon, ICON_LAYER_LINK);
		tip = g_strdup (_("Wired network connection"));

#ifdef ENABLE_NOTIFY		
		nma_send_event_notification (applet, NOTIFY_URGENCY_LOW,
							    _("Connection Established"),
							    _("You are now connected to the wired network."),
							    "nm-device-wired");
#endif

		handled = TRUE;
		break;
	default:
		break;
	}

	g_free (iface);

	if (tip) {
		gtk_status_icon_set_tooltip (applet->status_icon, tip);
		g_free (tip);
	}

	return handled;
}

static void
foo_device_state_changed (NMDevice *device, NMDeviceState state, gpointer user_data)
{
	NMApplet *applet = NM_APPLET (user_data);
	gboolean handled = FALSE;

	applet->animation_step = 0;
	if (applet->animation_id) {
		g_source_remove (applet->animation_id);
		applet->animation_id = 0;
	}

	if (NM_IS_DEVICE_802_3_ETHERNET (device))
		handled = foo_wired_state_change (NM_DEVICE_802_3_ETHERNET (device), state, applet);
	else if (NM_IS_DEVICE_802_11_WIRELESS (device))
		handled = foo_wireless_state_change (NM_DEVICE_802_11_WIRELESS (device), state, applet);

	if (!handled)
		foo_common_state_change (device, state, applet);
}

static void
foo_device_added_cb (NMClient *client, NMDevice *device, gpointer user_data)
{
	g_signal_connect (device, "state-changed",
				   G_CALLBACK (foo_device_state_changed),
				   user_data);

	foo_device_state_changed (device, nm_device_get_state (device), user_data);
}

static void
foo_add_initial_devices (gpointer data, gpointer user_data)
{
	NMApplet *applet = NM_APPLET (user_data);

	foo_device_added_cb (applet->nm_client, NM_DEVICE (data), applet);
}

static void
foo_client_state_change (NMClient *client, NMState state, gpointer user_data)
{
	NMApplet *applet = NM_APPLET (user_data);
	GdkPixbuf *pixbuf = NULL;
	char *tip = NULL;

	switch (state) {
	case NM_STATE_UNKNOWN:
		break;
	case NM_STATE_ASLEEP:
		pixbuf = applet->no_connection_icon;
		tip = g_strdup (_("Networking disabled"));
		break;
	case NM_STATE_DISCONNECTED:
		pixbuf = applet->no_connection_icon;
		tip = g_strdup (_("No network connection"));

#ifdef ENABLE_NOTIFY
		nma_send_event_notification (applet, NOTIFY_URGENCY_NORMAL, _("Disconnected"),
							    _("The network connection has been disconnected."),
							    "nm-no-connection");
#endif

		break;
	default:
		break;
	}

	if (pixbuf)
		foo_set_icon (applet, pixbuf, ICON_LAYER_LINK);

	if (tip) {
		gtk_status_icon_set_tooltip (applet->status_icon, tip);
		g_free (tip);
	}
}

static void
foo_setup_client_state_handlers (NMClient *client, NMApplet *applet)
{
	g_signal_connect (client, "state-change",
				   G_CALLBACK (foo_client_state_change),
				   applet);

	g_signal_connect (client, "device-added",
				   G_CALLBACK (foo_device_added_cb),
				   applet);
}


static void
foo_manager_running (NMClient *client,
				 gboolean running,
				 gpointer user_data)
{
	NMApplet *applet = NM_APPLET (user_data);

	gtk_status_icon_set_visible (applet->status_icon, running);

	if (running) {
		g_message ("NM appeared");

		/* Force the icon update */
		foo_client_state_change (client, nm_client_get_state (client), applet);
	} else {
		g_message ("NM disappeared");

		foo_client_state_change (client, NM_STATE_UNKNOWN, applet);
	}
}

static gboolean
foo_set_initial_state (gpointer data)
{
	NMApplet *applet = NM_APPLET (data);
	GSList *list;

	foo_manager_running (applet->nm_client, TRUE, applet);

	list = nm_client_get_devices (applet->nm_client);
	if (list) {
		g_slist_foreach (list, foo_add_initial_devices, applet);
		g_slist_free (list);
	}

	return FALSE;
}

static void
foo_client_setup (NMApplet *applet)
{
	NMClient *client;

	client = nm_client_new ();
	if (!client)
		return;

	applet->nm_client = client;

	foo_setup_client_state_handlers (client, applet);
	g_signal_connect (client, "manager-running",
				   G_CALLBACK (foo_manager_running), applet);

	if (nm_client_manager_is_running (client))
		g_idle_add (foo_set_initial_state, applet);
}

/*****************************************************************************/

/*
 * nma_finalize
 *
 * Destroy the applet and clean up its data
 *
 */
static void nma_finalize (GObject *object)
{
	NMApplet *applet = NM_APPLET (object);

	nma_menu_clear (applet);
	if (applet->top_menu_item)
		gtk_menu_item_remove_submenu (GTK_MENU_ITEM (applet->top_menu_item));

	nma_icons_free (applet);

//	nmi_passphrase_dialog_destroy (applet);
#ifdef ENABLE_NOTIFY
	if (applet->notification) {
		notify_notification_close (applet->notification, NULL);
		g_object_unref (applet->notification);
	}
#endif

	g_free (applet->glade_file);
	if (applet->info_dialog_xml)
		g_object_unref (applet->info_dialog_xml);
#ifndef HAVE_STATUS_ICON
	if (applet->tooltips)
		g_object_unref (applet->tooltips);
#endif

	g_object_unref (applet->gconf_client);

#ifdef HAVE_STATUS_ICON
	if (applet->status_icon)
		g_object_unref (applet->status_icon);
#else
	if (applet->tray_icon) {
		gtk_widget_destroy (GTK_WIDGET (applet->tray_icon));
		g_object_unref (applet->tray_icon);
	}
#endif /* HAVE_STATUS_ICON */

	g_hash_table_destroy (applet->vpn_connections);
	g_object_unref (applet->vpn_manager);
	g_object_unref (applet->nm_client);

	if (applet->nm_client)
		g_object_unref (applet->nm_client);

	G_OBJECT_CLASS (nma_parent_class)->finalize (object);
}

static GObject *nma_constructor (GType type, guint n_props, GObjectConstructParam *construct_props)
{
	NMApplet *applet;
	AppletDBusManager * dbus_mgr;

	applet = NM_APPLET (G_OBJECT_CLASS (nma_parent_class)->constructor (type, n_props, construct_props));

#ifndef HAVE_STATUS_ICON
	applet->tooltips = gtk_tooltips_new ();
	if (!applet->tooltips)
		goto error;
#endif

	applet->glade_file = g_build_filename (GLADEDIR, "applet.glade", NULL);
	if (!applet->glade_file || !g_file_test (applet->glade_file, G_FILE_TEST_IS_REGULAR)) {
		nma_schedule_warning_dialog (applet,
		                             _("The NetworkManager Applet could not find some required resources (the glade file was not found)."));
		goto error;
	}

	applet->info_dialog_xml = glade_xml_new (applet->glade_file, "info_dialog", NULL);
	if (!applet->info_dialog_xml)
        goto error;

	applet->gconf_client = gconf_client_get_default ();
	if (!applet->gconf_client)
	    goto error;

	/* Load pixmaps and create applet widgets */
	if (!nma_setup_widgets (applet))
	    goto error;
	nma_icons_init (applet);
	
	dbus_mgr = applet_dbus_manager_get ();
	if (dbus_mgr == NULL) {
		nm_warning ("Couldn't initialize the D-Bus manager.");
		g_object_unref (applet);
		return NULL;
	}

	applet->settings = applet_dbus_settings_new ();

    /* Start our DBus service */
    if (!applet_dbus_manager_start_service (dbus_mgr)) {
		g_object_unref (applet);
		return NULL;
    }

	foo_client_setup (applet);
	applet->vpn_manager = nm_vpn_manager_new ();
	applet->vpn_connections = g_hash_table_new_full (g_str_hash, g_str_equal,
										    (GDestroyNotify) g_free,
										    (GDestroyNotify) g_object_unref);

#ifndef HAVE_STATUS_ICON
	g_signal_connect (applet->tray_icon, "style-set", G_CALLBACK (nma_theme_change_cb), NULL);

	nma_icons_load_from_disk (applet);
#endif /* !HAVE_STATUS_ICON */

	return G_OBJECT (applet);

error:
	g_object_unref (applet);
	return NULL;
}


static void nma_icons_free (NMApplet *applet)
{
	int i;

	if (!applet->icons_loaded)
		return;

	for (i = 0; i <= ICON_LAYER_MAX; i++) {
		if (applet->icon_layers[i])
			g_object_unref (applet->icon_layers[i]);
	}

	if (applet->no_connection_icon)
		g_object_unref (applet->no_connection_icon);
	if (applet->wired_icon)
		g_object_unref (applet->wired_icon);
	if (applet->adhoc_icon)
		g_object_unref (applet->adhoc_icon);
	if (applet->vpn_lock_icon)
		g_object_unref (applet->vpn_lock_icon);

	if (applet->wireless_00_icon)
		g_object_unref (applet->wireless_00_icon);
	if (applet->wireless_25_icon)
		g_object_unref (applet->wireless_25_icon);
	if (applet->wireless_50_icon)
		g_object_unref (applet->wireless_50_icon);
	if (applet->wireless_75_icon)
		g_object_unref (applet->wireless_75_icon);
	if (applet->wireless_100_icon)
		g_object_unref (applet->wireless_100_icon);

	for (i = 0; i < NUM_CONNECTING_STAGES; i++) {
		int j;

		for (j = 0; j < NUM_CONNECTING_FRAMES; j++)
			if (applet->network_connecting_icons[i][j])
				g_object_unref (applet->network_connecting_icons[i][j]);
	}

	for (i = 0; i < NUM_VPN_CONNECTING_FRAMES; i++)
		if (applet->vpn_connecting_icons[i])
			g_object_unref (applet->vpn_connecting_icons[i]);

	nma_icons_zero (applet);
}

static void nma_icons_zero (NMApplet *applet)
{
	int i;

	applet->no_connection_icon = NULL;
	applet->wired_icon = NULL;
	applet->adhoc_icon = NULL;
	applet->vpn_lock_icon = NULL;

	applet->wireless_00_icon = NULL;
	applet->wireless_25_icon = NULL;
	applet->wireless_50_icon = NULL;
	applet->wireless_75_icon = NULL;
	applet->wireless_100_icon = NULL;

	for (i = 0; i < NUM_CONNECTING_STAGES; i++)
	{
		int j;

		for (j = 0; j < NUM_CONNECTING_FRAMES; j++)
			applet->network_connecting_icons[i][j] = NULL;
	}

	for (i = 0; i < NUM_VPN_CONNECTING_FRAMES; i++)
		applet->vpn_connecting_icons[i] = NULL;

	applet->icons_loaded = FALSE;
}

#define ICON_LOAD(x, y)	\
	{		\
		GError *err = NULL; \
		x = gtk_icon_theme_load_icon (applet->icon_theme, y, size, 0, &err); \
		if (x == NULL) { \
			success = FALSE; \
			g_warning ("Icon %s missing: %s", y, err->message); \
			g_error_free (err); \
			goto out; \
		} \
	}

static gboolean
nma_icons_load_from_disk (NMApplet *applet)
{
	int 		size, i;
	gboolean	success;

	/*
	 * NULL out the icons, so if we error and call nma_icons_free(), we don't hit stale
	 * data on the not-yet-reached icons.  This can happen off nma_icon_theme_changed().
	 */

	g_return_val_if_fail (!applet->icons_loaded, FALSE);

#ifdef HAVE_STATUS_ICON
	size = applet->size;
	if (size < 0)
		return FALSE;
#else
	size = 22; /* hard-coded */
#endif /* HAVE_STATUS_ICON */

	for (i = 0; i <= ICON_LAYER_MAX; i++)
		applet->icon_layers[i] = NULL;

	ICON_LOAD(applet->no_connection_icon, "nm-no-connection");
	ICON_LOAD(applet->wired_icon, "nm-device-wired");
	ICON_LOAD(applet->adhoc_icon, "nm-adhoc");
	ICON_LOAD(applet->vpn_lock_icon, "nm-vpn-lock");

	ICON_LOAD(applet->wireless_00_icon, "nm-signal-00");
	ICON_LOAD(applet->wireless_25_icon, "nm-signal-25");
	ICON_LOAD(applet->wireless_50_icon, "nm-signal-50");
	ICON_LOAD(applet->wireless_75_icon, "nm-signal-75");
	ICON_LOAD(applet->wireless_100_icon, "nm-signal-100");

	for (i = 0; i < NUM_CONNECTING_STAGES; i++)
	{
		int j;

		for (j = 0; j < NUM_CONNECTING_FRAMES; j++)
		{
			char *name;

			name = g_strdup_printf ("nm-stage%02d-connecting%02d", i+1, j+1);
			ICON_LOAD(applet->network_connecting_icons[i][j], name);
			g_free (name);
		}
	}

	for (i = 0; i < NUM_VPN_CONNECTING_FRAMES; i++)
	{
		char *name;

		name = g_strdup_printf ("nm-vpn-connecting%02d", i+1);
		ICON_LOAD(applet->vpn_connecting_icons[i], name);
		g_free (name);
	}

	success = TRUE;

out:
	if (!success)
	{
		char *msg = g_strdup(_("The NetworkManager applet could not find some required resources.  It cannot continue.\n"));
		show_warning_dialog (msg);
		nma_icons_free (applet);
	}

	return success;
}

static void nma_icon_theme_changed (GtkIconTheme *icon_theme, NMApplet *applet)
{
	nma_icons_free (applet);
	nma_icons_load_from_disk (applet);
}

static void nma_icons_init (NMApplet *applet)
{
	const char style[] =
		"style \"MenuBar\"\n"
		"{\n"
			"GtkMenuBar::shadow_type = GTK_SHADOW_NONE\n"
			"GtkMenuBar::internal-padding = 0\n"
		"}\n"
		"style \"MenuItem\"\n"
		"{\n"
			"xthickness=0\n"
			"ythickness=0\n"
		"}\n"
		"class \"GtkMenuBar\" style \"MenuBar\"\n"
		"widget \"*ToplevelMenu*\" style \"MenuItem\"\n";
	GdkScreen *screen;
	gboolean path_appended;

	if (applet->icon_theme)
	{
		g_signal_handlers_disconnect_by_func (applet->icon_theme,
						      G_CALLBACK (nma_icon_theme_changed),
						      applet);
	}

#ifdef HAVE_STATUS_ICON
#if GTK_CHECK_VERSION(2, 11, 0)
	screen = gtk_status_icon_get_screen (applet->status_icon);
#else
	screen = gdk_screen_get_default ();
#endif /* gtk 2.11.0 */
#else /* !HAVE_STATUS_ICON */
	screen = gtk_widget_get_screen (GTK_WIDGET (applet->tray_icon));
#endif /* HAVE_STATUS_ICON */
	
	applet->icon_theme = gtk_icon_theme_get_for_screen (screen);

	/* If not done yet, append our search path */
	path_appended = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (applet->icon_theme),
					 		    "NMAIconPathAppended"));
	if (path_appended == FALSE)
	{
		gtk_icon_theme_append_search_path (applet->icon_theme, ICONDIR);
		g_object_set_data (G_OBJECT (applet->icon_theme),
				   "NMAIconPathAppended",
				   GINT_TO_POINTER (TRUE));
	}

	g_signal_connect (applet->icon_theme, "changed", G_CALLBACK (nma_icon_theme_changed), applet);

	/* FIXME: Do we need to worry about other screens? */
	gtk_rc_parse_string (style);
}

NMApplet *
nm_applet_new ()
{
	return g_object_new (NM_TYPE_APPLET, NULL);
}

