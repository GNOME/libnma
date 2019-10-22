// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_WS_H
#define NMA_WS_H

typedef struct _NMAWs NMAWs;

#define NMA_TYPE_WS                (nma_ws_get_type ())
#define NMA_WS(obj)                (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMA_TYPE_WS, NMAWs))
#define NMA_IS_WS(obj)             (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMA_TYPE_WS))
#define NMA_WS_GET_INTERFACE(obj)  (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NMA_TYPE_WS, NMAWsInterface))

GType nma_ws_get_type (void);

gboolean nma_ws_validate (NMAWs *self, GError **error);

void nma_ws_add_to_size_group (NMAWs *self,
                               GtkSizeGroup *group);

void nma_ws_fill_connection (NMAWs *self,
                             NMConnection *connection);

void nma_ws_update_secrets (NMAWs *self,
                            NMConnection *connection);

gboolean nma_ws_adhoc_compatible (NMAWs *self);

gboolean nma_ws_hotspot_compatible (NMAWs *self);

#endif /* NMA_WS_H */
