/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
/***************************************************************************
 * CVSID: $Id: nm-vpn-ui-interface.h 846 2005-08-15 19:34:20Z caillon $
 *
 * nm-vpn-ui-interface.h : Public interface for VPN UI editing widgets
 *
 * Copyright (C) 2005 David Zeuthen, <davidz@redhat.com>
 *
 * === 
 * NOTE NOTE NOTE: All source for nm-vpn-properties is licensed to you
 * under your choice of the Academic Free License version 2.0, or the
 * GNU General Public License version 2.
 * ===
 *
 * Licensed under the Academic Free License version 2.0
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 **************************************************************************/

#ifndef NM_VPN_UI_INTERFACE_H
#define NM_VPN_UI_INTERFACE_H

#ifndef NM_VPN_API_SUBJECT_TO_CHANGE
#error "Please define NM_VPN_API_SUBJECT_TO_CHANGE to acknowledge your understanding that NetworkManager hasn't reached 1.0 and is subject to protocol and API churn. See the README for a full explanation."
#endif

#include <gtk/gtk.h>
#include <nm-connection.h>

struct _NetworkManagerVpnUI;
typedef struct _NetworkManagerVpnUI NetworkManagerVpnUI;

typedef void (*NetworkManagerVpnUIDialogValidityCallback) (NetworkManagerVpnUI *self,
							   gboolean is_valid, 
							   gpointer user_data);


struct _NetworkManagerVpnUI {
	const char *(*get_display_name) (NetworkManagerVpnUI *self);

	const char *(*get_service_name) (NetworkManagerVpnUI *self);

	void (*fill_connection) (NetworkManagerVpnUI *self, NMConnection *connection);

	GtkWidget *(*get_widget) (NetworkManagerVpnUI *self, NMConnection *connection);

	void (*set_validity_changed_callback) (NetworkManagerVpnUI *self, 
					       NetworkManagerVpnUIDialogValidityCallback cb,
					       gpointer user_data);

	gboolean (*is_valid) (NetworkManagerVpnUI *self);

	/*
	 * get_confirmation_details:
	 * retval is allocated and must be freed
	 */
	void (*get_confirmation_details)(NetworkManagerVpnUI *self, gchar **retval);

	gboolean (*can_export) (NetworkManagerVpnUI *self);

	gboolean (*import_file) (NetworkManagerVpnUI *self,
	                         const char *path,
	                         NMConnection *connection);

	gboolean (*export) (NetworkManagerVpnUI *self, NMConnection *connection);

	gpointer data;
};

#endif /* NM_VPN_UI_INTERFACE_H */

