// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2007 - 2021 Red Hat, Inc.
 */

#ifndef NMA_WS_802_1X_PRIVATE_H
#define NMA_WS_802_1X_PRIVATE_H

#if !defined(NMA_COMPILATION)
#error "This is an internal header, available only when building libnma."
#endif

#include <gtk/gtk.h>
#include <glib.h>

#include <NetworkManager.h>

struct _NMAWs8021xClass {
	GtkGridClass parent;
};

struct _NMAWs8021x {
	GtkGrid parent;

	GtkWidget *eap_auth_combo;
	GtkWidget *eap_auth_label;
	GtkBox *eap_vbox;
	GtkWidget *eap_widget;

	NMConnection *connection;
	gboolean secrets_only;
	gboolean is_editor;
	char **secrets_hints;

	char *username, *password;
	gboolean always_ask, show_password;
};

void nma_ws_802_1x_fill_connection (NMAWs *ws, NMConnection *connection);

void nma_ws_802_1x_set_userpass (NMAWs8021x *self,
                                 const char *user,
                                 const char *password,
                                 gboolean always_ask,
                                 gboolean show_password);

#endif /* NMA_WS_802_1X_PRIVATE_H */
