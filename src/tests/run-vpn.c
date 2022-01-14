// SPDX-License-Identifier: GPL-2.0+
/*
 * run-vpn - VPN plugin runner for testing
 *
 * Copyright (C) 2018 Lubomir Rintel
 * Copyright (C) 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <NetworkManager.h>
#include <gtk/gtk.h>
#include <stdlib.h>

static gboolean
window_deleted (GMainLoop *main_loop)
{
	g_main_loop_quit (main_loop);
	return FALSE;
}

static void
changed_cb (NMVpnEditor *editor, gpointer user_data)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_free_error GError *error = NULL;

	g_printerr ("=== CHANGED ===\n");

	connection = nm_simple_connection_new ();
	if (!nm_vpn_editor_update_connection (editor, connection, &error)) {
		g_printerr ("Error: %s\n", error->message);
	} else {
		nm_connection_dump (connection);
	}
}

int
main (int argc, char *argv[])
{
	gs_unref_object NMVpnEditorPlugin *plugin = NULL;
	gs_unref_object NMVpnEditor *editor = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_free char *service_type = NULL;
	GMainLoop *main_loop;
	GtkWidget *window;
	GtkWidget *widget;
	gs_free_error GError *error = NULL;

	gtk_init ();

	if (argc != 2) {
		g_printerr ("Usage: %s libnm-vpn-plugin-<name>.so\n", argv[0]);
		return EXIT_FAILURE;
	}

	plugin = nm_vpn_editor_plugin_load (argv[1], NULL, &error);
	if (!plugin) {
		g_printerr ("Error: %s\n", error->message);
		return EXIT_FAILURE;
	}

	g_object_get (G_OBJECT (plugin), "service", &service_type, NULL);
	g_return_val_if_fail (service_type, EXIT_FAILURE);

	connection = nm_simple_connection_new ();
	nm_connection_add_setting (connection,
		g_object_new (NM_TYPE_SETTING_VPN,
		              "service-type", service_type,
		              NULL));

	editor = nm_vpn_editor_plugin_get_editor (plugin, connection, &error);
	if (!editor) {
		g_printerr ("Error: %s\n", error->message);
		return EXIT_FAILURE;
	}
	g_signal_connect (G_OBJECT (editor), "changed", G_CALLBACK (changed_cb), NULL);

	main_loop = g_main_loop_new (NULL, FALSE);
	window = gtk_window_new ();
	gtk_widget_show (window);

#if GTK_CHECK_VERSION(4,0,0)
	g_signal_connect_swapped (window, "close-request", G_CALLBACK (window_deleted), main_loop);
#else
	g_signal_connect_swapped (window, "delete-event", G_CALLBACK (window_deleted), main_loop);
#endif

	widget = GTK_WIDGET (nm_vpn_editor_get_widget (editor));
	gtk_widget_show (widget);
	gtk_window_set_child (GTK_WINDOW (window), widget);
	g_main_loop_run (main_loop);
	g_main_loop_unref (main_loop);

	return EXIT_SUCCESS;
}
