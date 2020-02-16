// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_WS_PRIVATE_H
#define NMA_WS_PRIVATE_H

typedef struct {
	GTypeInterface parent;

	void (*add_to_size_group) (NMAWs *self, GtkSizeGroup *group);
	void (*fill_connection)   (NMAWs *self, NMConnection *connection);
	void (*update_secrets)    (NMAWs *self, NMConnection *connection);
	gboolean (*validate)      (NMAWs *self, GError **error);

	gboolean adhoc_compatible;
	gboolean hotspot_compatible;
} NMAWsInterface;

void nma_ws_changed_cb (GtkWidget *entry, gpointer user_data);

void nma_ws_clear_ciphers (NMConnection *connection);

#endif /* NMA_WS_PRIVATE_H */
