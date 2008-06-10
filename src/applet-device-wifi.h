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

#ifndef __APPLET_DEVICE_WIFI_H__
#define __APPLET_DEVICE_WIFI_H__

#include <gtk/gtkwidget.h>

#include "applet.h"

NMADeviceClass *applet_device_wifi_get_class (NMApplet *applet);

void nma_menu_add_other_network_item (GtkWidget *menu, NMApplet *applet);
void nma_menu_add_create_network_item (GtkWidget *menu, NMApplet *applet);

#endif /* __APPLET_DEVICE_WIFI_H__ */
