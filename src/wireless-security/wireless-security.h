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

#ifndef WIRELESS_SECURITY_H
#define WIRELESS_SECURITY_H

#include <glib.h>
#include <gtk/gtk.h>
#include <gtk/gtksizegroup.h>
#include <glade/glade.h>

#include <nm-connection.h>

typedef struct _WirelessSecurity WirelessSecurity;

typedef void (*WSChangedFunc) (WirelessSecurity *sec, gpointer user_data);

typedef void (*WSAddToSizeGroupFunc) (WirelessSecurity *sec, GtkSizeGroup *group);
typedef void (*WSFillConnectionFunc) (WirelessSecurity *sec, NMConnection *connection);
typedef void (*WSDestroyFunc) (WirelessSecurity *sec);
typedef gboolean (*WSValidateFunc) (WirelessSecurity *sec, const GByteArray *ssid);

struct _WirelessSecurity {
	guint32 refcount;
	GladeXML *xml;
	GtkWidget *ui_widget;
	WSChangedFunc changed_notify;
	gpointer changed_notify_data;

	WSAddToSizeGroupFunc add_to_size_group;
	WSFillConnectionFunc fill_connection;
	WSValidateFunc validate;
	WSDestroyFunc destroy;
};

#define WIRELESS_SECURITY(x) ((WirelessSecurity *) x)


GtkWidget *wireless_security_get_widget (WirelessSecurity *sec);

void wireless_security_set_changed_notify (WirelessSecurity *sec,
                                           WSChangedFunc func,
                                           gpointer user_data);

gboolean wireless_security_validate (WirelessSecurity *sec, const GByteArray *ssid);

void wireless_security_add_to_size_group (WirelessSecurity *sec,
                                          GtkSizeGroup *group);

void wireless_security_fill_connection (WirelessSecurity *sec,
                                        NMConnection *connection);

WirelessSecurity *wireless_security_ref (WirelessSecurity *sec);

void wireless_security_unref (WirelessSecurity *sec);

GType wireless_security_get_g_type (void);

/* Below for internal use only */

#include "ws-wep-key.h"
#include "ws-wep-passphrase.h"
#include "ws-wpa-psk.h"
#include "ws-leap.h"
#include "ws-wpa-eap.h"

void wireless_security_init (WirelessSecurity *sec,
                             WSValidateFunc validate,
                             WSAddToSizeGroupFunc add_to_size_group,
                             WSFillConnectionFunc fill_connection,
                             WSDestroyFunc destroy,
                             GladeXML *xml,
                             GtkWidget *ui_widget);

void wireless_security_changed_cb (GtkWidget *entry, gpointer user_data);

void ws_wep_fill_connection (NMConnection *connection,
                             const char *key,
                             gint auth_alg);

void ws_wpa_fill_default_ciphers (NMConnection *connection);

#endif /* WIRELESS_SECURITY_H */

