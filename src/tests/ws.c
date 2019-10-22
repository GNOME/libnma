// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include <gtk/gtk.h>

#include "nma-ws.h"

static gboolean
delete (GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
        gtk_main_quit ();

        return FALSE;
}

static void
ws_changed_cb (NMAWs *ws, gpointer user_data)
{
	NMConnection *connection = user_data;
	GError *error = NULL;

	nma_ws_fill_connection (ws, connection);
	g_print ("\n=== Connection dump ===\n");
	nm_connection_dump (connection);

	if (nma_ws_validate (ws, &error))
		return;

	g_print ("*** Validation error: %s\n", error->message);
	g_error_free (error);
}

int
main (int argc, char *argv[])
{
	GtkWidget *w;
	GtkWidget *notebook;
	NMConnection *connection = NULL;
	const char *hints[] = { "hello", "world", NULL };

	connection = nm_simple_connection_new ();
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

	notebook = gtk_notebook_new ();
	gtk_widget_show (notebook);
	gtk_container_add (GTK_CONTAINER (w), notebook);

	w = GTK_WIDGET (nma_ws_sae_new (connection, FALSE));
	gtk_widget_show (w);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), w, gtk_label_new ("SAE"));
	nma_ws_add_to_size_group (NMA_WS (w), gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL));
	g_signal_connect (w, "ws-changed", G_CALLBACK (ws_changed_cb), connection);
	ws_changed_cb (NMA_WS (w), connection);

	w = GTK_WIDGET (nma_ws_leap_new (connection, FALSE));
	gtk_widget_show (w);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), w, gtk_label_new ("LEAP"));
	nma_ws_add_to_size_group (NMA_WS (w), gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL));
	g_signal_connect (w, "ws-changed", G_CALLBACK (ws_changed_cb), connection);
	ws_changed_cb (NMA_WS (w), connection);

	w = GTK_WIDGET (nma_ws_wpa_psk_new (connection, FALSE));
	gtk_widget_show (w);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), w, gtk_label_new ("WPA PSK"));
	nma_ws_add_to_size_group (NMA_WS (w), gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL));
	g_signal_connect (w, "ws-changed", G_CALLBACK (ws_changed_cb), connection);
	ws_changed_cb (NMA_WS (w), connection);

	w = GTK_WIDGET (nma_ws_wep_key_new (connection, NM_WEP_KEY_TYPE_UNKNOWN, FALSE, FALSE));
	gtk_widget_show (w);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), w, gtk_label_new ("WEP Key"));
	nma_ws_add_to_size_group (NMA_WS (w), gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL));
	g_signal_connect (w, "ws-changed", G_CALLBACK (ws_changed_cb), connection);
	ws_changed_cb (NMA_WS (w), connection);

	w = GTK_WIDGET (nma_ws_802_1x_new (connection, FALSE, FALSE));
	gtk_widget_show (w);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), w, gtk_label_new ("802.1x"));
	nma_ws_add_to_size_group (NMA_WS (w), gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL));
	g_signal_connect (w, "ws-changed", G_CALLBACK (ws_changed_cb), connection);
	ws_changed_cb (NMA_WS (w), connection);

	w = GTK_WIDGET (nma_ws_dynamic_wep_new (connection, FALSE, FALSE));
	gtk_widget_show (w);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), w, gtk_label_new ("Dynamic WEP"));
	nma_ws_add_to_size_group (NMA_WS (w), gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL));
	g_signal_connect (w, "ws-changed", G_CALLBACK (ws_changed_cb), connection);
	ws_changed_cb (NMA_WS (w), connection);

	w = GTK_WIDGET (nma_ws_wpa_eap_new (connection, FALSE, FALSE, hints));
	gtk_widget_show (w);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), w, gtk_label_new ("WPA EAP"));
	nma_ws_add_to_size_group (NMA_WS (w), gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL));
	g_signal_connect (w, "ws-changed", G_CALLBACK (ws_changed_cb), connection);
	ws_changed_cb (NMA_WS (w), connection);

	gtk_main ();
}
