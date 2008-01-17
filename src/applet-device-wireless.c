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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <iwlib.h>

#include <glib/gi18n.h>
#include <gtk/gtkwidget.h>
#include <gtk/gtkmenuitem.h>
#include <gtk/gtkcheckmenuitem.h>

#include <nm-device.h>
#include <nm-access-point.h>
#include <nm-setting-connection.h>
#include <nm-setting-wireless.h>
#include <nm-device-802-11-wireless.h>
#include <nm-utils.h>

#include "applet.h"
#include "applet-dbus-settings.h"
#include "applet-device-wireless.h"
#include "ap-menu-item.h"
#include "utils.h"
#include "gnome-keyring-md5.h"
#include "wireless-dialog.h"

static void wireless_dialog_response_cb (GtkDialog *dialog, gint response, gpointer user_data);

static void
other_wireless_activate_cb (GtkWidget *menu_item,
                            NMApplet *applet)
{
	GtkWidget *dialog;

	dialog = nma_wireless_dialog_new (applet->glade_file,
	                                  applet->nm_client,
	                                  NULL,
	                                  NULL,
	                                  NULL,
	                                  FALSE);
	if (!dialog)
		return;

	g_signal_connect (dialog, "response",
	                  G_CALLBACK (wireless_dialog_response_cb),
	                  applet);

	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER_ALWAYS);
	gtk_widget_realize (dialog);
	gdk_x11_window_set_user_time (dialog->window, gtk_get_current_event_time ());
	gtk_window_present (GTK_WINDOW (dialog));
}

void
nma_menu_add_other_network_item (GtkWidget *menu, NMApplet *applet)
{
	GtkWidget *menu_item;
	GtkWidget *label;

	menu_item = gtk_menu_item_new ();
	label = gtk_label_new_with_mnemonic (_("_Connect to Other Wireless Network..."));
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	gtk_container_add (GTK_CONTAINER (menu_item), label);
	gtk_widget_show_all (menu_item);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), menu_item);
	g_signal_connect (menu_item, "activate", G_CALLBACK (other_wireless_activate_cb), applet);
}

static void
new_network_activate_cb (GtkWidget *menu_item, NMApplet *applet)
{
	GtkWidget *dialog;

	dialog = nma_wireless_dialog_new (applet->glade_file,
	                                  applet->nm_client,
	                                  NULL,
	                                  NULL,
	                                  NULL,
	                                  TRUE);
	if (!dialog)
		return;

	g_signal_connect (dialog, "response",
	                  G_CALLBACK (wireless_dialog_response_cb),
	                  applet);

	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER_ALWAYS);
	gtk_widget_realize (dialog);
	gdk_x11_window_set_user_time (dialog->window, gtk_get_current_event_time ());
	gtk_window_present (GTK_WINDOW (dialog));
}

void
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
	g_signal_connect (menu_item, "activate", G_CALLBACK (new_network_activate_cb), applet);
}



typedef struct {
	NMApplet *applet;
	NMDevice80211Wireless *device;
	NMAccessPoint *ap;
} WirelessMenuItemInfo;

static void
wireless_menu_item_info_destroy (gpointer data)
{
	g_slice_free (WirelessMenuItemInfo, data);
}

static const char * default_ssid_list[] = {
	"linksys",
	"linksys-a",
	"linksys-g",
	"default",
	"belkin54g",
	"NETGEAR",
	NULL
};

static gboolean
is_manufacturer_default_ssid (const GByteArray *ssid)
{
	const char **default_ssid = default_ssid_list;

	while (*default_ssid) {
		if (ssid->len == strlen (*default_ssid)) {
			if (!memcmp (*default_ssid, ssid->data, ssid->len))
				return TRUE;
		}
		default_ssid++;
	}
	return FALSE;
}

static GSList *
add_ciphers_from_flags (guint32 flags, gboolean pairwise)
{
	GSList *ciphers = NULL;

	if (pairwise) {
		if (flags & NM_802_11_AP_SEC_PAIR_TKIP)
			ciphers = g_slist_append (ciphers, g_strdup ("tkip"));
		if (flags & NM_802_11_AP_SEC_PAIR_CCMP)
			ciphers = g_slist_append (ciphers, g_strdup ("ccmp"));
	} else {
		if (flags & NM_802_11_AP_SEC_GROUP_WEP40)
			ciphers = g_slist_append (ciphers, g_strdup ("wep40"));
		if (flags & NM_802_11_AP_SEC_GROUP_WEP104)
			ciphers = g_slist_append (ciphers, g_strdup ("wep104"));
		if (flags & NM_802_11_AP_SEC_GROUP_TKIP)
			ciphers = g_slist_append (ciphers, g_strdup ("tkip"));
		if (flags & NM_802_11_AP_SEC_GROUP_CCMP)
			ciphers = g_slist_append (ciphers, g_strdup ("ccmp"));
	}

	return ciphers;
}

static NMSettingWirelessSecurity *
get_security_for_ap (NMAccessPoint *ap, guint32 dev_caps, gboolean *supported)
{
	NMSettingWirelessSecurity *sec;
	int mode;
	guint32 flags;
	guint32 wpa_flags;
	guint32 rsn_flags;

	g_return_val_if_fail (NM_IS_ACCESS_POINT (ap), NULL);
	g_return_val_if_fail (supported != NULL, NULL);
	g_return_val_if_fail (*supported == TRUE, NULL);

	sec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();

	mode = nm_access_point_get_mode (ap);
	flags = nm_access_point_get_flags (ap);
	wpa_flags = nm_access_point_get_wpa_flags (ap);
	rsn_flags = nm_access_point_get_rsn_flags (ap);

	/* No security */
	if (   !(flags & NM_802_11_AP_FLAGS_PRIVACY)
	    && (wpa_flags == NM_802_11_AP_SEC_NONE)
	    && (rsn_flags == NM_802_11_AP_SEC_NONE))
		goto none;

	/* Static WEP, Dynamic WEP, or LEAP */
	if (   (flags & NM_802_11_AP_FLAGS_PRIVACY)
	    && (wpa_flags == NM_802_11_AP_SEC_NONE)
	    && (rsn_flags == NM_802_11_AP_SEC_NONE)) {
		sec->key_mgmt = g_strdup ("none");
		sec->wep_tx_keyidx = 0;
		return sec;
	}

	/* Stuff after this point requires infrastructure */
	if (mode != IW_MODE_INFRA) {
		*supported = FALSE;
		goto none;
	}

	/* WPA2 PSK first */
	if (   (rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
	    && (dev_caps & NM_802_11_DEVICE_CAP_RSN)) {
		sec->key_mgmt = g_strdup ("wpa-psk");
		sec->proto = g_slist_append (sec->proto, g_strdup ("rsn"));
		sec->pairwise = add_ciphers_from_flags (rsn_flags, TRUE);
		sec->group = add_ciphers_from_flags (rsn_flags, FALSE);
		return sec;
	}

	/* WPA PSK */
	if (   (wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_PSK)
	    && (dev_caps & NM_802_11_DEVICE_CAP_WPA)) {
		sec->key_mgmt = g_strdup ("wpa-psk");
		sec->proto = g_slist_append (sec->proto, g_strdup ("wpa"));
		sec->pairwise = add_ciphers_from_flags (wpa_flags, TRUE);
		sec->group = add_ciphers_from_flags (wpa_flags, FALSE);
		return sec;
	}

	/* WPA2 Enterprise */
	if (   (rsn_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
	    && (dev_caps & NM_802_11_DEVICE_CAP_RSN)) {
		sec->key_mgmt = g_strdup ("wpa-eap");
		sec->proto = g_slist_append (sec->proto, g_strdup ("rsn"));
		sec->pairwise = add_ciphers_from_flags (rsn_flags, TRUE);
		sec->group = add_ciphers_from_flags (rsn_flags, FALSE);
		sec->eap = g_slist_append (sec->eap, g_strdup ("ttls"));
		sec->phase2_auth = g_strdup ("mschapv2");
		return sec;
	}

	/* WPA Enterprise */
	if (   (wpa_flags & NM_802_11_AP_SEC_KEY_MGMT_802_1X)
	    && (dev_caps & NM_802_11_DEVICE_CAP_WPA)) {
		sec->key_mgmt = g_strdup ("wpa-eap");
		sec->proto = g_slist_append (sec->proto, g_strdup ("wpa"));
		sec->pairwise = add_ciphers_from_flags (wpa_flags, TRUE);
		sec->group = add_ciphers_from_flags (wpa_flags, FALSE);
		sec->eap = g_slist_append (sec->eap, g_strdup ("ttls"));
		sec->phase2_auth = g_strdup ("mschapv2");
		return sec;
	}

	*supported = FALSE;

none:
	g_object_unref (sec);
	return NULL;
}

static NMConnection *
wireless_new_auto_connection (NMDevice *device,
                              NMApplet *applet,
                              gpointer user_data)
{
	WirelessMenuItemInfo *info = (WirelessMenuItemInfo *) user_data;
	NMConnection *connection = NULL;
	NMSettingConnection *s_con = NULL;
	NMSettingWireless *s_wireless = NULL;
	NMSettingWirelessSecurity *s_wireless_sec = NULL;
	const GByteArray *ap_ssid;
	char buf[33];
	int buf_len;
	int mode;
	guint32 dev_caps;
	gboolean supported = TRUE;

	if (!info->ap) {
		g_warning ("%s: AP not set", __func__);
		return NULL;
	}

	s_wireless = (NMSettingWireless *) nm_setting_wireless_new ();

	ap_ssid = nm_access_point_get_ssid (info->ap);
	s_wireless->ssid = g_byte_array_sized_new (ap_ssid->len);
	g_byte_array_append (s_wireless->ssid, ap_ssid->data, ap_ssid->len);

	mode = nm_access_point_get_mode (info->ap);
	if (mode == IW_MODE_ADHOC)
		s_wireless->mode = g_strdup ("adhoc");
	else if (mode == IW_MODE_INFRA)
		s_wireless->mode = g_strdup ("infrastructure");
	else
		g_assert_not_reached ();

	dev_caps = nm_device_802_11_wireless_get_capabilities (NM_DEVICE_802_11_WIRELESS (device));
	s_wireless_sec = get_security_for_ap (info->ap, dev_caps, &supported);
	if (!supported) {
		g_object_unref (s_wireless);
		goto out;
	} else if (s_wireless_sec) {
		s_wireless->security = g_strdup (NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
	}

	connection = nm_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wireless));
	if (s_wireless_sec)
		nm_connection_add_setting (connection, NM_SETTING (s_wireless_sec));

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	s_con->type = g_strdup (NM_SETTING (s_wireless)->name);

	memset (buf, 0, sizeof (buf));
	buf_len = MIN(ap_ssid->len, sizeof (buf) - 1);
	memcpy (buf, ap_ssid->data, buf_len);
	s_con->id = g_strdup_printf ("Auto %s", nm_utils_ssid_to_utf8 (buf, buf_len));

	/* Only utoconnect APs that don't use the manufacturer default SSID. */
	s_con->autoconnect = !is_manufacturer_default_ssid (ap_ssid);

	nm_connection_add_setting (connection, NM_SETTING (s_con));

out:
	return connection;
}

static gboolean
wireless_connection_filter (NMConnection *connection,
                            NMDevice *device,
                            NMApplet *applet,
                            gpointer user_data)
{
	WirelessMenuItemInfo *info = (WirelessMenuItemInfo *) user_data;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	const GByteArray *ap_ssid;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (strcmp (s_con->type, NM_SETTING_WIRELESS_SETTING_NAME))
		return FALSE;

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
	if (!s_wireless)
		return FALSE;

	ap_ssid = nm_access_point_get_ssid (info->ap);
	if (!nm_utils_same_ssid (s_wireless->ssid, ap_ssid, TRUE))
		return FALSE;

	if (!utils_check_ap_compatible (info->ap, connection))
		return FALSE;

	return TRUE;
}

static void
wireless_menu_item_activate (GtkMenuItem *item, gpointer user_data)
{
	WirelessMenuItemInfo *info = (WirelessMenuItemInfo *) user_data;
	const char *specific_object = NULL;

	if (info->ap)
		specific_object = nm_object_get_path (NM_OBJECT (info->ap));
	applet_menu_item_activate_helper (NM_DEVICE (info->device),
	                                  info->applet,
	                                  specific_object ? specific_object : "/",
	                                  user_data);
}

#define AP_HASH_LEN 16

struct dup_data {
	NMDevice * device;
	GtkWidget * found;
	guchar * hash;
};

static void
find_duplicate (GtkWidget * widget, gpointer user_data)
{
	struct dup_data * data = (struct dup_data *) user_data;
	NMDevice *device;
	const guchar * hash;
	guint32 hash_len = 0;

	g_return_if_fail (data);
	g_return_if_fail (data->hash);

	if (data->found || !NM_IS_NETWORK_MENU_ITEM (widget))
		return;

	device = g_object_get_data (G_OBJECT (widget), "device");
	if (NM_DEVICE (device) != data->device)
		return;

	hash = nm_network_menu_item_get_hash (NM_NETWORK_MENU_ITEM (widget), &hash_len);
	if (hash == NULL || hash_len != AP_HASH_LEN)
		return;

	if (memcmp (hash, data->hash, AP_HASH_LEN) == 0)
		data->found = widget;
}

static void
add_one_ap_menu_item (NMDevice80211Wireless *device,
                      NMAccessPoint *ap,
                      NMAccessPoint *active_ap,
                      GtkWidget *menu,
                      NMApplet *applet)
{
	const GByteArray *ssid;
	gint8 strength;
	struct dup_data dup_data = { NULL, NULL };
	NMNetworkMenuItem *item = NULL;

	/* Don't add BSSs that hide their SSID */
	ssid = nm_access_point_get_ssid (ap);
	if (!ssid || nm_utils_is_empty_ssid (ssid->data, ssid->len))
		return;

	strength = nm_access_point_get_strength (ap);

	dup_data.found = NULL;
	dup_data.hash = g_object_get_data (G_OBJECT (ap), "hash");
	if (!dup_data.hash)
		return;
	dup_data.device = NM_DEVICE (device);
	gtk_container_foreach (GTK_CONTAINER (menu),
	                       find_duplicate,
	                       &dup_data);

	if (dup_data.found) {
		item = NM_NETWORK_MENU_ITEM (dup_data.found);

		/* Just update strength if greater than what's there */
		if (nm_network_menu_item_get_strength (item) > strength)
			nm_network_menu_item_set_strength (item, strength);

		nm_network_menu_item_add_dupe (item, ap);
	} else {
		WirelessMenuItemInfo *info;
		GtkWidget *foo;

		foo = nm_network_menu_item_new (applet->encryption_size_group,
		                                dup_data.hash, AP_HASH_LEN);
		item = NM_NETWORK_MENU_ITEM (foo);
		nm_network_menu_item_set_ssid (item, (GByteArray *) ssid);
		nm_network_menu_item_set_strength (item, strength);
		nm_network_menu_item_set_detail (item, ap, applet->adhoc_icon);
		nm_network_menu_item_add_dupe (item, ap);

		g_object_set_data (G_OBJECT (item), "device", NM_DEVICE (device));

		gtk_menu_shell_append (GTK_MENU_SHELL (menu), GTK_WIDGET (item));

		info = g_slice_new0 (WirelessMenuItemInfo);
		info->applet = applet;
		info->device = device;
		info->ap = ap;

		g_signal_connect_data (GTK_WIDGET (item),
		                       "activate",
		                       G_CALLBACK (wireless_menu_item_activate),
		                       info,
		                       (GClosureNotify) wireless_menu_item_info_destroy,
		                       0);

		gtk_widget_show_all (GTK_WIDGET (item));
	}

	if (!active_ap)
		return;

	g_signal_handlers_block_matched (item, G_SIGNAL_MATCH_FUNC, 0, 0, NULL,
	                                 G_CALLBACK (wireless_menu_item_activate), NULL);

	if (nm_network_menu_item_find_dupe (item, active_ap))
		gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (item), TRUE);

	g_signal_handlers_unblock_matched (item, G_SIGNAL_MATCH_FUNC, 0, 0, NULL,
	                                   G_CALLBACK (wireless_menu_item_activate), NULL);
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

static gboolean
label_expose (GtkWidget *widget)
{
	/* Bad hack to make the label draw normally, instead of insensitive. */
	widget->state = GTK_STATE_NORMAL;
  
	return FALSE;
}

static void
wireless_add_menu_item (NMDevice *device,
                        guint32 n_devices,
                        GtkWidget *menu,
                        NMApplet *applet)
{
	WirelessMenuItemInfo *info;
	NMDevice80211Wireless *wdev;
	char *text;
	GtkMenuItem *item;
	GSList *aps;
	GSList *iter;
	NMAccessPoint *active_ap = NULL;

	wdev = NM_DEVICE_802_11_WIRELESS (device);
	aps = nm_device_802_11_wireless_get_access_points (wdev);

	if (n_devices > 1) {
		const char *desc;
		char *dev_name = NULL;

		desc = utils_get_device_description (device);
		if (desc)
			dev_name = g_strdup (desc);
		if (!dev_name)
			dev_name = nm_device_get_iface (device);
		text = g_strdup_printf (ngettext ("Wireless Network (%s)", "Wireless Networks (%s)",
										  g_slist_length (aps)), dev_name);
		g_free (dev_name);
	} else
		text = g_strdup (ngettext ("Wireless Network", "Wireless Networks", g_slist_length (aps)));

	item = GTK_MENU_ITEM (gtk_menu_item_new_with_mnemonic (text));
	g_free (text);

	g_signal_connect (item, "expose-event", G_CALLBACK (label_expose), NULL);
	gtk_widget_set_sensitive (GTK_WIDGET (item), FALSE);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), GTK_WIDGET (item));
	gtk_widget_show (GTK_WIDGET (item));

	info = g_slice_new0 (WirelessMenuItemInfo);
	info->applet = applet;
	info->device = wdev;

	g_signal_connect_data (item, "activate",
	                       G_CALLBACK (wireless_menu_item_activate),
	                       info,
	                       (GClosureNotify) wireless_menu_item_info_destroy, 0);

	/* Don't display APs when wireless is disabled */
	if (!nm_client_wireless_get_enabled (applet->nm_client))
		goto out;

	aps = nm_device_802_11_wireless_get_access_points (wdev);
	active_ap = nm_device_802_11_wireless_get_active_access_point (wdev);

	/* Add all networks in our network list to the menu */
	aps = g_slist_sort (aps, sort_wireless_networks);
	for (iter = aps; iter; iter = g_slist_next (iter))
		add_one_ap_menu_item (wdev, NM_ACCESS_POINT (iter->data), active_ap, menu, applet);

out:
	g_slist_free (aps);
}

static gboolean
add_seen_bssid (AppletDbusConnectionSettings *connection, NMAccessPoint *ap)
{
	NMSettingWireless *s_wireless;
	gboolean found = FALSE;
	gboolean added = FALSE;
	char *lower_bssid;
	GSList *iter;
	const char *bssid;
	
	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection->connection,
													 NM_TYPE_SETTING_WIRELESS));
	if (!s_wireless)
		return FALSE;

	bssid = nm_access_point_get_hw_address (ap);
	if (!bssid || !utils_ether_addr_valid (ether_aton (bssid)))
		return FALSE;

	lower_bssid = g_ascii_strdown (bssid, -1);
	if (!lower_bssid)
		return FALSE;

	for (iter = s_wireless->seen_bssids; iter; iter = g_slist_next (iter)) {
		char *lower_seen_bssid = g_ascii_strdown (iter->data, -1);

		if (!strcmp (lower_seen_bssid, lower_bssid)) {
			found = TRUE;
			g_free (lower_seen_bssid);
			break;
		}
		g_free (lower_seen_bssid);
	}

	/* Add this AP's BSSID to the seen-BSSIDs list */
	if (!found) {
		s_wireless->seen_bssids = g_slist_prepend (s_wireless->seen_bssids,
		                                           g_strdup (lower_bssid));
		added = TRUE;
	}
	g_free (lower_bssid);
	return added;
}

static void
notify_active_ap_changed_cb (NMDevice80211Wireless *device,
                             GParamSpec *pspec,
                             NMApplet *applet)
{
	AppletDbusConnectionSettings *connection_settings = NULL;
	NMSettingWireless *s_wireless;
	NMAccessPoint *ap;
	const GByteArray *ssid;

	if (nm_device_get_state (NM_DEVICE (device)) != NM_DEVICE_STATE_ACTIVATED)
		return;

	ap = nm_device_802_11_wireless_get_active_access_point (device);
	if (!ap)
		return;

	connection_settings = applet_get_connection_settings_for_device (NM_DEVICE (device), applet);
	if (!connection_settings)
		return;

	s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection_settings->connection,
													 NM_TYPE_SETTING_WIRELESS));
	if (!s_wireless)
		return;

	ssid = nm_access_point_get_ssid (ap);
	if (!ssid || !nm_utils_same_ssid (s_wireless->ssid, ssid, TRUE))
		return;

	if (add_seen_bssid (connection_settings, ap))
		applet_dbus_connection_settings_save (NM_CONNECTION_SETTINGS (connection_settings));		

	applet_schedule_update_icon (applet);
}

static guchar *
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

static void
add_hash_to_ap (NMAccessPoint *ap)
{
	guchar *hash = ap_hash (ap);
	g_object_set_data_full (G_OBJECT (ap),
	                        "hash", hash,
	                        (GDestroyNotify) g_free);
}

static void
notify_ap_prop_changed_cb (NMAccessPoint *ap,
                           GParamSpec *pspec,
                           NMApplet *applet)
{
	const char *prop = g_param_spec_get_name (pspec);

	if (   !strcmp (prop, NM_ACCESS_POINT_FLAGS)
	    || !strcmp (prop, NM_ACCESS_POINT_WPA_FLAGS)
	    || !strcmp (prop, NM_ACCESS_POINT_RSN_FLAGS)
	    || !strcmp (prop, NM_ACCESS_POINT_SSID)
	    || !strcmp (prop, NM_ACCESS_POINT_FREQUENCY)
	    || !strcmp (prop, NM_ACCESS_POINT_MODE)) {
		add_hash_to_ap (ap);
	}
}

static void
access_point_added_cb (NMDevice80211Wireless *device,
                       NMAccessPoint *ap,
                       gpointer user_data)
{
	NMApplet *applet = NM_APPLET  (user_data);

	add_hash_to_ap (ap);
	g_signal_connect (G_OBJECT (ap),
	                  "notify",
	                  G_CALLBACK (notify_ap_prop_changed_cb),
	                  applet);
}

static void
wireless_device_added (NMDevice *device, NMApplet *applet)
{
	NMDevice80211Wireless *wdev = NM_DEVICE_802_11_WIRELESS (device);
	GSList *aps, *iter;

	g_signal_connect (wdev,
	                  "notify::" NM_DEVICE_802_11_WIRELESS_ACTIVE_ACCESS_POINT,
	                  G_CALLBACK (notify_active_ap_changed_cb),
	                  applet);

	g_signal_connect (wdev,
	                  "access-point-added",
	                  G_CALLBACK (access_point_added_cb),
	                  applet);

	/* Hash all APs this device knows about */
	aps = nm_device_802_11_wireless_get_access_points (wdev);
	for (iter = aps; iter; iter = g_slist_next (iter)) {
		NMAccessPoint *ap = NM_ACCESS_POINT (iter->data);
		add_hash_to_ap (ap);
	}
	g_slist_free (aps);
}

static void
bssid_strength_changed (NMAccessPoint *ap, GParamSpec *pspec, gpointer user_data)
{
	applet_schedule_update_icon (NM_APPLET (user_data));
}

static void
wireless_device_state_changed (NMDevice *device,
                               NMDeviceState state,
                               NMApplet *applet)
{
	AppletDbusConnectionSettings *connection_settings;
	NMAccessPoint *ap = NULL;
	char *msg;
	char *esc_ssid = NULL;

	if (state == NM_DEVICE_STATE_PREPARE ||
	    state == NM_DEVICE_STATE_CONFIG ||
	    state == NM_DEVICE_STATE_IP_CONFIG ||
	    state == NM_DEVICE_STATE_NEED_AUTH ||
	    state == NM_DEVICE_STATE_ACTIVATED) {
		ap = nm_device_802_11_wireless_get_active_access_point (NM_DEVICE_802_11_WIRELESS (device));
	}

	if (!ap || (ap != applet->current_ap)) {
		if (applet->current_ap) {
			g_signal_handlers_disconnect_by_func (applet->current_ap,
			                                      G_CALLBACK (bssid_strength_changed),
			                                      applet);
			g_object_unref (applet->current_ap);
			applet->current_ap = NULL;
		}

		if (ap)
			applet->current_ap = g_object_ref (ap);
	}

	if (state != NM_DEVICE_STATE_ACTIVATED)
		return;

	if (applet->current_ap) {
		const GByteArray *ssid = nm_access_point_get_ssid (applet->current_ap);

		if (ssid)
			esc_ssid = (char *) nm_utils_escape_ssid (ssid->data, ssid->len);

		g_object_ref (applet->current_ap);
		g_signal_connect (applet->current_ap,
		                  "notify::" NM_ACCESS_POINT_STRENGTH,
		                  G_CALLBACK (bssid_strength_changed),
		                  applet);

		/* Save this BSSID to seen-bssids list */
		connection_settings = applet_get_connection_settings_for_device (device, applet);
		if (connection_settings && add_seen_bssid (connection_settings, applet->current_ap))
			applet_dbus_connection_settings_save (NM_CONNECTION_SETTINGS (connection_settings));
	}

	msg = g_strdup_printf (_("You are now connected to the wireless network '%s'."),
	                       esc_ssid ? esc_ssid : _("(none)"));
	applet_do_notify (applet, NOTIFY_URGENCY_LOW, _("Connection Established"),
					  msg, "nm-device-wireless");
	g_free (msg);
}

static GdkPixbuf *
wireless_get_icon (NMDevice *device,
                   NMDeviceState state,
                   char **tip,
                   NMApplet *applet)
{
	GdkPixbuf *pixbuf = NULL;
	char *iface;
	char *esc_ssid = _("(none)");

	iface = nm_device_get_iface (device);

	if (applet->current_ap) {
		const GByteArray *ssid;

		ssid = nm_access_point_get_ssid (applet->current_ap);
		if (ssid)
			esc_ssid = (char *) nm_utils_escape_ssid (ssid->data, ssid->len);
	}

	switch (state) {
	case NM_DEVICE_STATE_PREPARE:
		*tip = g_strdup_printf (_("Preparing device %s for the wireless network '%s'..."), iface, esc_ssid);
		break;
	case NM_DEVICE_STATE_CONFIG:
		*tip = g_strdup_printf (_("Attempting to join the wireless network '%s'..."), esc_ssid);
		break;
	case NM_DEVICE_STATE_IP_CONFIG:
		*tip = g_strdup_printf (_("Requesting a network address from the wireless network '%s'..."), esc_ssid);
		break;
	case NM_DEVICE_STATE_NEED_AUTH:
		*tip = g_strdup_printf (_("Waiting for Network Key for the wireless network '%s'..."), esc_ssid);
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		if (applet->current_ap) {
			guint32 strength;

			strength = nm_access_point_get_strength (applet->current_ap);
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

			*tip = g_strdup_printf (_("Wireless network connection to '%s' (%d%%)"),
			                        esc_ssid, strength);
		} else {
			pixbuf = applet->wireless_00_icon;
			*tip = g_strdup_printf (_("Wireless network connection to '%s'"), esc_ssid);
		}
		break;
	default:
		break;
	}

	g_free (iface);
	return pixbuf;
}

static void
activate_device_cb (gpointer user_data, GError *err)
{
	if (err) {
		nm_warning ("Device Activation failed: %s", err->message);
	}
}

static gboolean
wireless_dialog_close (gpointer user_data)
{
	GtkWidget *dialog = GTK_WIDGET (user_data);

	gtk_dialog_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);
	return FALSE;
}

#define NAG_IGNORED_TAG "nag-ignored"

static void
nag_dialog_response_cb (GtkDialog *nag_dialog,
                        gint response,
                        gpointer user_data)
{
	GtkWidget *wireless_dialog = GTK_WIDGET (user_data);

	if (response == GTK_RESPONSE_NO) {  /* user opted not to correct the warning */
		g_object_set_data (G_OBJECT (wireless_dialog),
		                   NAG_IGNORED_TAG,
		                   GUINT_TO_POINTER (TRUE));
		g_idle_add (wireless_dialog_close, wireless_dialog);
	}
}

static void
wireless_dialog_response_cb (GtkDialog *dialog,
                             gint response,
                             gpointer user_data)
{
	NMApplet *applet = NM_APPLET (user_data);
	NMConnection *connection = NULL;
	NMDevice *device = NULL;
	NMAccessPoint *ap = NULL;
	NMSettingConnection *s_con;
	AppletDbusConnectionSettings *exported_con = NULL;
	const char *con_path;
	gboolean ignored = FALSE;

	if (response != GTK_RESPONSE_OK)
		goto done;

	ignored = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (dialog), NAG_IGNORED_TAG));
	if (!ignored) {
		GtkWidget *nag_dialog;

		/* Nag the user about certificates or whatever.  Only destroy the dialog
		 * if no nagging was done.
		 */
		nag_dialog = nma_wireless_dialog_nag_user (GTK_WIDGET (dialog));
		if (nag_dialog) {
			gtk_window_set_transient_for (GTK_WINDOW (nag_dialog), GTK_WINDOW (dialog));
			g_signal_connect (nag_dialog, "response",
			                  G_CALLBACK (nag_dialog_response_cb),
			                  dialog);
			return;
		}
	}

	connection = nma_wireless_dialog_get_connection (GTK_WIDGET (dialog), &device, &ap);
	g_assert (connection);
	g_assert (device);
	// FIXME: find a compatible connection in the current connection list before adding
	// a new connection

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	if (!s_con->id) {
		NMSettingWireless *s_wireless;
		char *ssid;

		s_wireless = NM_SETTING_WIRELESS (nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS));
		ssid = nm_utils_ssid_to_utf8 ((const char *) s_wireless->ssid->data, s_wireless->ssid->len);
		s_con->id = g_strdup_printf ("Auto %s", ssid);
		g_free (ssid);

		// FIXME: don't autoconnect until the connection is successful at least once
		/* Don't autoconnect adhoc networks by default for now */
		if (!s_wireless->mode || !strcmp (s_wireless->mode, "infrastructure"))
			s_con->autoconnect = TRUE;
	}

	exported_con = applet_dbus_settings_get_by_connection (APPLET_DBUS_SETTINGS (applet->settings),
	                                                       connection);
	if (!exported_con) {
		exported_con = applet_dbus_settings_add_connection (APPLET_DBUS_SETTINGS (applet->settings),
		                                                    connection);
		if (!exported_con) {
			nm_warning ("Couldn't create other network connection.");
			goto done;
		}
	} else {
		/* Save the updated settings to GConf */
		applet_dbus_connection_settings_save (NM_CONNECTION_SETTINGS (exported_con));
	}

	con_path = nm_connection_settings_get_dbus_object_path (NM_CONNECTION_SETTINGS (exported_con));
	nm_client_activate_device (applet->nm_client,
	                           device,
	                           NM_DBUS_SERVICE_USER_SETTINGS,
	                           con_path,
	                           ap ? nm_object_get_path (NM_OBJECT (ap)) : NULL,
	                           activate_device_cb,
	                           applet);

done:
	gtk_widget_hide (GTK_WIDGET (dialog));
	gtk_widget_destroy (GTK_WIDGET (dialog));
}

static void
wireless_get_more_info (NMDevice *device,
                        NMConnection *connection,
                        NMApplet *applet,
                        gpointer user_data)
{
	WirelessMenuItemInfo *info = (WirelessMenuItemInfo *) user_data;
	GtkWidget *dialog;

	dialog = nma_wireless_dialog_new (applet->glade_file,
	                                  applet->nm_client,
	                                  connection,
	                                  device,
	                                  info->ap,
	                                  FALSE);
	g_return_if_fail (dialog != NULL);

	g_signal_connect (dialog, "response",
	                  G_CALLBACK (wireless_dialog_response_cb),
	                  applet);

	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER_ALWAYS);
	gtk_widget_realize (dialog);
	gtk_window_present (GTK_WINDOW (dialog));
}

static void
get_secrets_dialog_response_cb (GtkDialog *dialog,
                                gint response,
                                gpointer user_data)
{
	NMApplet *applet = NM_APPLET (user_data);
	DBusGMethodInvocation *context;
	AppletDbusConnectionSettings *applet_connection;
	NMConnection *connection = NULL;
	NMDevice *device = NULL;
	GHashTable *setting_hash;
	const char *setting_name;
	NMSetting *setting;
	GError *error = NULL;
	gboolean ignored;

	context = g_object_get_data (G_OBJECT (dialog), "dbus-context");
	setting_name = g_object_get_data (G_OBJECT (dialog), "setting-name");
	if (!context || !setting_name) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d (%s): couldn't get dialog data",
		             __FILE__, __LINE__, __func__);
		goto done;
	}

	if (response != GTK_RESPONSE_OK) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d (%s): canceled",
		             __FILE__, __LINE__, __func__);
		goto done;
	}

	ignored = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (dialog), NAG_IGNORED_TAG));
	if (!ignored) {
		GtkWidget *widget;

		/* Nag the user about certificates or whatever.  Only destroy the dialog
		 * if no nagging was done.
		 */
		widget = nma_wireless_dialog_nag_user (GTK_WIDGET (dialog));
		if (widget) {
			gtk_window_set_transient_for (GTK_WINDOW (widget), GTK_WINDOW (dialog));
			g_signal_connect (widget, "response",
			                  G_CALLBACK (nag_dialog_response_cb),
			                  dialog);
			return;
		}
	}

	connection = nma_wireless_dialog_get_connection (GTK_WIDGET (dialog), &device, NULL);
	if (!connection) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d (%s): couldn't get connection from wireless dialog.",
		             __FILE__, __LINE__, __func__);
		goto done;
	}

	setting = nm_connection_get_setting_by_name (connection, setting_name);
	if (!setting) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d (%s): requested setting '%s' didn't exist in the "
		             " connection.",
		             __FILE__, __LINE__, __func__, setting_name);
		goto done;
	}

	utils_fill_connection_certs (connection);
	setting_hash = nm_setting_to_hash (setting);
	utils_clear_filled_connection_certs (connection);

	if (!setting_hash) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d (%s): failed to hash setting '%s'.",
		             __FILE__, __LINE__, __func__, setting_name);
		goto done;
	}

	dbus_g_method_return (context, setting_hash);
	g_hash_table_destroy (setting_hash);

	/* Save the connection back to GConf _after_ hashing it, because
	 * saving to GConf might trigger the GConf change notifiers, resulting
	 * in the connection being read back in from GConf which clears secrets.
	 */
	applet_connection = applet_dbus_settings_get_by_connection (APPLET_DBUS_SETTINGS (applet->settings), connection);
	if (applet_connection)
		applet_dbus_connection_settings_save (NM_CONNECTION_SETTINGS (applet_connection));

done:
	if (error) {
		g_warning (error->message);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}

	if (connection)
		nm_connection_clear_secrets (connection);
	gtk_widget_hide (GTK_WIDGET (dialog));
	gtk_widget_destroy (GTK_WIDGET (dialog));
}

static gboolean
wireless_get_secrets (NMDevice *device,
                      NMConnection *connection,
                      const char *specific_object,
                      const char *setting_name,
                      DBusGMethodInvocation *context,
                      NMApplet *applet,
                      GError **error)
{
	NMAccessPoint *ap;
	GtkWidget *dialog;

	g_assert (specific_object);
	ap = nm_device_802_11_wireless_get_access_point_by_path (NM_DEVICE_802_11_WIRELESS (device),
	                                                         specific_object);

	dialog = nma_wireless_dialog_new (applet->glade_file,
	                                  applet->nm_client,
	                                  connection,
	                                  device,
	                                  ap,
	                                  FALSE);
	if (!dialog) {
		g_set_error (error, NM_SETTINGS_ERROR, 1,
		             "%s.%d (%s): couldn't display secrets UI",
		             __FILE__, __LINE__, __func__);
		return FALSE;
	}

	g_object_set_data (G_OBJECT (dialog), "dbus-context", context);
	g_object_set_data_full (G_OBJECT (dialog),
	                        "setting-name", g_strdup (setting_name),
	                        (GDestroyNotify) g_free);

	g_signal_connect (dialog, "response",
	                  G_CALLBACK (get_secrets_dialog_response_cb),
	                  applet);

	gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER_ALWAYS);
	gtk_widget_realize (dialog);
	gtk_window_present (GTK_WINDOW (dialog));

	return TRUE;
}

NMADeviceClass *
applet_device_wireless_get_class (NMApplet *applet)
{
	NMADeviceClass *dclass;

	dclass = g_slice_new0 (NMADeviceClass);
	if (!dclass)
		return NULL;

	dclass->new_auto_connection = wireless_new_auto_connection;
	dclass->connection_filter = wireless_connection_filter;
	dclass->add_menu_item = wireless_add_menu_item;
	dclass->device_added = wireless_device_added;
	dclass->device_state_changed = wireless_device_state_changed;
	dclass->get_icon = wireless_get_icon;
	dclass->get_more_info = wireless_get_more_info;
	dclass->get_secrets = wireless_get_secrets;

	return dclass;
}

