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
 * Copyright (C) 2018 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <gtk/gtk.h>
#include "nma-cert-chooser.h"

int
main (int argc, char *argv[])
{
	GMainLoop *loop;
	GtkWidget *dialog;
	GtkBox *content;
	GtkWidget *widget;

	gtk_init ();

	dialog = gtk_dialog_new_with_buttons ("NMACertChooser test",
	                                      NULL, GTK_DIALOG_MODAL,
	                                      "Dismiss",  GTK_RESPONSE_DELETE_EVENT,
	                                      NULL);
	content = GTK_BOX (gtk_dialog_get_content_area (GTK_DIALOG (dialog)));
	gtk_orientable_set_orientation (GTK_ORIENTABLE (content), GTK_ORIENTATION_VERTICAL);

#if GTK_CHECK_VERSION(4,0,0)
	gtk_box_set_spacing (content, 6);
#endif

	widget = nma_cert_chooser_new ("Any", 0);
	gtk_widget_show (widget);
	gtk_box_append (content, widget);

	widget = gtk_separator_new (GTK_ORIENTATION_HORIZONTAL);
	gtk_widget_show (widget);
	gtk_box_append (content, widget);

	widget = nma_cert_chooser_new ("FLAG_PASSWORDS", NMA_CERT_CHOOSER_FLAG_PASSWORDS);
	nma_cert_chooser_set_cert (NMA_CERT_CHOOSER (widget),
	                           "pkcs11:object=praise;type=satan",
	                           NM_SETTING_802_1X_CK_SCHEME_PKCS11);
	nma_cert_chooser_set_key_uri (NMA_CERT_CHOOSER (widget),
	                              "pkcs11:object=worship;type=doom");
	gtk_widget_show (widget);
	gtk_box_append (content, widget);

	widget = gtk_separator_new (GTK_ORIENTATION_HORIZONTAL);
	gtk_widget_show (widget);
	gtk_box_append (content, widget);

	widget = nma_cert_chooser_new ("FLAG_CERT", NMA_CERT_CHOOSER_FLAG_CERT);
	gtk_widget_show (widget);
	gtk_box_append (content, widget);

	widget = gtk_separator_new (GTK_ORIENTATION_HORIZONTAL);
	gtk_widget_show (widget);
	gtk_box_append (content, widget);

	widget = nma_cert_chooser_new ("FLAG_PEM", NMA_CERT_CHOOSER_FLAG_PEM);
	gtk_widget_show (widget);
	gtk_box_append (content, widget);

	widget = nma_cert_chooser_new ("FLAG_NO_PASSWORDS", NMA_CERT_CHOOSER_FLAG_NO_PASSWORDS);
	gtk_widget_show (widget);
	gtk_box_append (content, widget);

	loop = g_main_loop_new (NULL, FALSE);
	g_signal_connect_swapped (dialog, "response", G_CALLBACK (g_main_loop_quit), loop);

	gtk_window_set_hide_on_close (GTK_WINDOW (dialog), TRUE);
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);
	gtk_window_present (GTK_WINDOW (dialog));

	g_main_loop_run (loop);
	g_main_loop_unref (loop);
}
