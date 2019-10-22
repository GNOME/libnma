/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public License as
 * published by the ree Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * Copyright 2018, 2019 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <stdio.h>
#include <string.h>

#include <gtk/gtk.h>

//#include "nma-bar-code-widget.h"
#include "wireless-security/wireless-security.h"

static gboolean
delete (GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
        gtk_main_quit ();

        return FALSE;
}

int
main (int argc, char *argv[])
{
	GtkWidget *w;
//	GtkWidget *w, *pass;
	GtkWidget *grid;
	NMConnection *connection = NULL;
	gs_unref_bytes GBytes *ssid = g_bytes_new_static ("\"ab:cd\"", 13);

	connection = nm_simple_connection_new ();
	nm_connection_add_setting (connection,
		g_object_new (NM_TYPE_SETTING_CONNECTION,
		              NM_SETTING_CONNECTION_ID, "fifik",
		              NULL));
	nm_connection_add_setting (connection,
	                           nm_setting_wireless_new ());

#if GTK_CHECK_VERSION(3,90,0)
	gtk_init ();
#else
	gtk_init (&argc, &argv);
#endif

	w = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_widget_show (w);
	g_signal_connect (w, "delete-event", G_CALLBACK (delete), NULL);

	grid = gtk_grid_new ();
	gtk_widget_show (grid);
	gtk_grid_set_column_spacing (GTK_GRID (grid), 64);
	gtk_grid_set_row_spacing (GTK_GRID (grid), 64);
	g_object_set (grid,
	              "margin_start", 6,
	              "margin_end", 6,
	              "margin_top", 6,
	              "margin_bottom", 6,
	              NULL);
	gtk_container_add (GTK_CONTAINER (w), grid);

{
	WirelessSecurity *sec = (WirelessSecurity *) ws_dynamic_wep_new (connection, FALSE, FALSE);
	w = wireless_security_get_widget (sec);
	gtk_widget_show (w);
	gtk_grid_attach (GTK_GRID (grid), w, 0, 0, 1, 4);
}

{
	WirelessSecurity *sec = (WirelessSecurity *) ws_leap_new (connection, FALSE);
	w = wireless_security_get_widget (sec);
	gtk_widget_show (w);
	gtk_grid_attach (GTK_GRID (grid), w, 1, 0, 1, 1);
}

{
	WirelessSecurity *sec = (WirelessSecurity *) ws_sae_new (connection, FALSE);
	w = wireless_security_get_widget (sec);
	gtk_widget_show (w);
	gtk_grid_attach (GTK_GRID (grid), w, 1, 1, 1, 1);
}

{
	WirelessSecurity *sec = (WirelessSecurity *) ws_wep_key_new (connection, NM_WEP_KEY_TYPE_UNKNOWN, FALSE, FALSE);
	w = wireless_security_get_widget (sec);
	gtk_widget_show (w);
	gtk_grid_attach (GTK_GRID (grid), w, 1, 2, 1, 1);
}

{
	WirelessSecurity *sec = (WirelessSecurity *) ws_wpa_psk_new (connection, FALSE);
	w = wireless_security_get_widget (sec);
	gtk_widget_show (w);
	gtk_grid_attach (GTK_GRID (grid), w, 1, 3, 1, 1);
}

{
	WirelessSecurity *sec = (WirelessSecurity *) ws_wpa_eap_new (connection, FALSE, FALSE, NULL);
	w = wireless_security_get_widget (sec);
	gtk_widget_show (w);
	gtk_grid_attach (GTK_GRID (grid), w, 2, 0, 1, 4);
}

	gtk_main ();
}
