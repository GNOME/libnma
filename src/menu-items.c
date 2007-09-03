/* menu-info.c - Class to represent the 
 *
 * Jonathan Blandford <jrb@redhat.com>
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
 * This also uses code from eel-vfs-extentions available under the LGPL:
 *     Authors: Darin Adler <darin@eazel.com>
 * 	    Pavel Cisler <pavel@eazel.com>
 * 	    Mike Fleming  <mfleming@eazel.com>
 *       John Sullivan <sullivan@eazel.com>
 *
 * (C) Copyright 2004 Red Hat, Inc.
 * (C) Copyright 1999, 2000 Eazel, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <glib/gi18n.h>
#include <string.h>
#include <iwlib.h>

#include "menu-items.h"
#include "nm-access-point.h"


/****************************************************************
 *   Wired menu item
 ****************************************************************/

GtkMenuItem *
wired_menu_item_new (NMDevice8023Ethernet *device,
					 gint n_devices)
{
	char *text;
	GtkCheckMenuItem *item;

	g_return_val_if_fail (NM_IS_DEVICE_802_3_ETHERNET (device), NULL);

	if (n_devices > 1) {
		char *dev_name;

		dev_name = nm_device_get_description (NM_DEVICE (device));
		if (!dev_name)
			dev_name = nm_device_get_iface (NM_DEVICE (device));
		text = g_strdup_printf (_("Wired Network (%s)"), dev_name);
		g_free (dev_name);
	} else
		text = g_strdup (_("_Wired Network"));

	item = GTK_CHECK_MENU_ITEM (gtk_check_menu_item_new_with_mnemonic (text));
	g_free (text);

	gtk_check_menu_item_set_draw_as_radio (item, TRUE);
	gtk_check_menu_item_set_active (item, nm_device_get_state (NM_DEVICE (device)) == NM_DEVICE_STATE_ACTIVATED);

	/* Only dim the item if the device supports carrier detection AND
	 * we know it doesn't have a link.
	 */
	/* FIXME */
/* 	if (nm_device_get_capabilities (device) & NM_DEVICE_CAP_CARRIER_DETECT) */
/* 		gtk_widget_set_sensitive (GTK_WIDGET (item), nm_device_get_link (device)); */

	return GTK_MENU_ITEM (item);
}

/****************************************************************
 *   Wireless menu item
 ****************************************************************/

static gboolean
label_expose (GtkWidget *widget)
{
	/* Bad hack to make the label draw normally, instead of insensitive. */
	widget->state = GTK_STATE_NORMAL;
  
	return FALSE;
}

GtkMenuItem *
wireless_menu_item_new (NMDevice80211Wireless *device,
						gint n_devices)
{
	char *text;
	GtkMenuItem *item;
	GSList *networks;

	g_return_val_if_fail (NM_IS_DEVICE_802_11_WIRELESS (device), NULL);

	networks = nm_device_802_11_wireless_get_networks (device);

	if (n_devices > 1) {
		char *dev_name;

		dev_name = nm_device_get_description (NM_DEVICE (device));
		if (!dev_name)
			dev_name = nm_device_get_iface (NM_DEVICE (device));
		text = g_strdup_printf (ngettext ("Wireless Network (%s)", "Wireless Networks (%s)",
										  g_slist_length (networks)), dev_name);
		g_free (dev_name);
	} else
		text = g_strdup (ngettext ("Wireless Network", "Wireless Networks", g_slist_length (networks)));

	g_slist_free (networks);

	item = GTK_MENU_ITEM (gtk_menu_item_new_with_mnemonic (text));
	g_free (text);

	g_signal_connect (item, "expose-event", G_CALLBACK (label_expose), NULL);
	gtk_widget_set_sensitive (GTK_WIDGET (item), FALSE);

	return item;
}

/****************************************************************
 *   Wireless Network menu item
 ****************************************************************/

G_DEFINE_TYPE (NMNetworkMenuItem, nm_network_menu_item, GTK_TYPE_CHECK_MENU_ITEM);

static void
nm_network_menu_item_init (NMNetworkMenuItem * item)
{
	GtkWidget * hbox;
	PangoFontDescription * fontdesc;
	PangoFontMetrics * metrics;
	PangoContext * context;
	PangoLanguage * lang;
	int ascent;

	gtk_check_menu_item_set_draw_as_radio (GTK_CHECK_MENU_ITEM (item), TRUE);
	hbox = gtk_hbox_new (FALSE, 6);
	item->ssid = gtk_label_new (NULL);
	gtk_misc_set_alignment (GTK_MISC (item->ssid), 0.0, 0.5);

	item->detail = gtk_image_new ();

	gtk_container_add (GTK_CONTAINER (item), hbox);
	gtk_box_pack_start (GTK_BOX (hbox), item->ssid, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (hbox), item->detail, FALSE, FALSE, 0);

	item->strength = gtk_progress_bar_new ();
	
	/* get the font ascent for the current font and language */
	context = gtk_widget_get_pango_context (item->strength);
	fontdesc = pango_context_get_font_description (context);
	lang = pango_context_get_language (context);
	metrics = pango_context_get_metrics (context, fontdesc, lang);
	ascent = pango_font_metrics_get_ascent (metrics) * 1.5 / PANGO_SCALE;
	pango_font_metrics_unref (metrics);

	/* size our progress bar to be five ascents long */
	gtk_widget_set_size_request (item->strength, ascent * 5, -1);

	gtk_box_pack_end (GTK_BOX (hbox), item->strength, FALSE, TRUE, 0);

	gtk_widget_show (item->ssid);
	gtk_widget_show (item->strength);
	gtk_widget_show (item->detail);
	gtk_widget_show (hbox);
}

GtkWidget*
nm_network_menu_item_new (GtkSizeGroup * size_group,
                          guchar * hash,
                          guint32 hash_len)
{
	NMNetworkMenuItem * item;

	item = g_object_new (NM_TYPE_NETWORK_MENU_ITEM, NULL);
	if (item == NULL)
		return NULL;

	item->destroyed = FALSE;
	item->int_strength = 0;
	if (hash && hash_len) {
		item->hash = g_malloc0 (hash_len);
		memcpy (item->hash, hash, hash_len);
		item->hash_len = hash_len;
	}
	if (size_group)
		gtk_size_group_add_widget (size_group, item->detail);

	return GTK_WIDGET (item);
}

static void
nm_network_menu_item_class_init (NMNetworkMenuItemClass * klass)
{
}

void
nm_network_menu_item_set_ssid (NMNetworkMenuItem * item, GByteArray * ssid)
{
	char * display_ssid = NULL;
	char buf[IW_ESSID_MAX_SIZE + 1];

	g_return_if_fail (item != NULL);
	g_return_if_fail (ssid != NULL);

	memset (buf, 0, sizeof (buf));
	memcpy (buf, ssid->data, MIN (ssid->len, sizeof (buf) - 1));
	display_ssid = nm_menu_network_escape_essid_for_display (buf);
	if (display_ssid) {
		gtk_label_set_text (GTK_LABEL (item->ssid), display_ssid);
		g_free (display_ssid);
	} else {
		gtk_label_set_text (GTK_LABEL (item->ssid), "");
	}
}

guint32
nm_network_menu_item_get_strength (NMNetworkMenuItem * item)
{
	g_return_val_if_fail (item != NULL, 0);

	return item->int_strength;
}

void
nm_network_menu_item_set_strength (NMNetworkMenuItem * item, guint32 strength)
{
	double percent;

	g_return_if_fail (item != NULL);

	item->int_strength = CLAMP (strength, 0, 100);
	percent = (double) item->int_strength / 100.0;
	gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (item->strength), percent);
}

const guchar *
nm_network_menu_item_get_hash (NMNetworkMenuItem * item,
                               guint32 * length)
{
	g_return_val_if_fail (item != NULL, NULL);
	g_return_val_if_fail (length != NULL, NULL);

	*length = item->hash_len;
	return item->hash;
}

void
nm_network_menu_item_set_detail (NMNetworkMenuItem * item,
                                 NMAccessPoint * ap,
                                 GdkPixbuf * adhoc_icon)
{
	gboolean encrypted = FALSE, adhoc = FALSE;
	guint32 flags, wpa_flags, rsn_flags;

	flags = nm_access_point_get_flags (ap);
	wpa_flags = nm_access_point_get_wpa_flags (ap);
	rsn_flags = nm_access_point_get_rsn_flags (ap);

	if (   (flags & NM_802_11_AP_FLAGS_PRIVACY)
	    || (wpa_flags != NM_802_11_AP_SEC_NONE)
	    || (rsn_flags != NM_802_11_AP_SEC_NONE))
		encrypted = TRUE;

	if (nm_access_point_get_mode (ap) == IW_MODE_ADHOC)
		adhoc = TRUE;

	if (adhoc) {
		gtk_image_set_from_pixbuf (GTK_IMAGE (item->detail), adhoc_icon);
	} else if (encrypted) {
		if (gtk_icon_theme_has_icon (gtk_icon_theme_get_default (), "network-wireless-encrypted"))
			gtk_image_set_from_icon_name (GTK_IMAGE (item->detail), "network-wireless-encrypted", GTK_ICON_SIZE_MENU);
		else
			gtk_image_set_from_icon_name (GTK_IMAGE (item->detail), "gnome-lockscreen", GTK_ICON_SIZE_MENU);
	} else {
		gtk_image_set_from_stock (GTK_IMAGE (item->detail), NULL, GTK_ICON_SIZE_MENU);
	}
}


/****************************************************************
 *   Utility stuff
 ****************************************************************/

/* This is copied from eel.
 */
static char *eel_make_valid_utf8 (const char *name)
{
	GString *string;
	const char *rem, *invalid;
	int remaining_bytes, valid_bytes;

	string = NULL;
	rem = name;
	remaining_bytes = strlen (name);

	while (remaining_bytes != 0) {
		if (g_utf8_validate (rem, remaining_bytes, &invalid)) {
			break;
		}
		valid_bytes = invalid - rem;

		if (string == NULL) {
			string = g_string_sized_new (remaining_bytes);
		}
		g_string_append_len (string, rem, valid_bytes);
		g_string_append_c (string, '?');

		remaining_bytes -= valid_bytes + 1;
		rem = invalid + 1;
	}

	if (string == NULL) {
		return g_strdup (name);
	}

	g_string_append (string, rem);
	g_string_append (string, _(" (invalid Unicode)"));
	g_assert (g_utf8_validate (string->str, -1, NULL));

	return g_string_free (string, FALSE);
}

char *nm_menu_network_escape_essid_for_display (const char *essid)
{
	if (g_utf8_validate (essid, -1, NULL))
		return g_strdup (essid);
	else
		return eel_make_valid_utf8 (essid);
}
