// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2019 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <gtk/gtk.h>

#include "nma-ws.h"

static gboolean
delete (GMainLoop *main_loop)
{
	g_main_loop_quit (main_loop);
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
	GMainLoop *loop;
	GtkWidget *w;
	GtkWidget *notebook;
	NMConnection *connection = NULL;
	const char *hints[] = { "hello", "world", NULL };

	connection = nm_simple_connection_new ();
	nm_connection_add_setting (connection,
	                           nm_setting_wireless_new ());

	gtk_init ();
	w = gtk_window_new ();
	gtk_widget_show (w);
	loop = g_main_loop_new (NULL, TRUE);
#if GTK_CHECK_VERSION(4,0,0)
	g_signal_connect_swapped (w, "close-request", G_CALLBACK (delete), loop);
#else
	g_signal_connect_swapped (w, "delete-event", G_CALLBACK (delete), loop);
#endif

	notebook = gtk_notebook_new ();
	gtk_widget_show (notebook);
	gtk_window_set_child (GTK_WINDOW (w), notebook);

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

	w = GTK_WIDGET (nma_ws_owe_new (connection));
	gtk_widget_show (w);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), w, gtk_label_new ("OWE"));
	nma_ws_add_to_size_group (NMA_WS (w), gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL));
	g_signal_connect (w, "ws-changed", G_CALLBACK (ws_changed_cb), connection);
	ws_changed_cb (NMA_WS (w), connection);

	g_main_loop_run (loop);
	g_main_loop_unref (loop);
}
