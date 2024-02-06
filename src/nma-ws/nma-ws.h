// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_WS_H
#define NMA_WS_H

#include <gtk/gtk.h>
#include <glib.h>
#include <glib-object.h>

#include <NetworkManager.h>

#include "nma-version.h"

G_BEGIN_DECLS

typedef struct _NMAWs NMAWs;
typedef struct _NMAWsInterface NMAWsInterface;

#if defined(G_DEFINE_AUTOPTR_CLEANUP_FUNC) && NMA_VERSION_MIN_REQUIRED >= NMA_VERSION_1_10_6
G_DEFINE_AUTOPTR_CLEANUP_FUNC(NMAWs, g_object_unref)
#endif

#define NMA_TYPE_WS                (nma_ws_get_type ())
#define NMA_WS(obj)                (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMA_TYPE_WS, NMAWs))
#define NMA_IS_WS(obj)             (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMA_TYPE_WS))
#define NMA_WS_GET_INTERFACE(obj)  (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NMA_TYPE_WS, NMAWsInterface))

NMA_AVAILABLE_IN_1_8_28
GType nma_ws_get_type (void);

NMA_AVAILABLE_IN_1_8_28
gboolean nma_ws_validate (NMAWs *self, GError **error);

NMA_AVAILABLE_IN_1_8_28
void nma_ws_add_to_size_group (NMAWs *self,
                               GtkSizeGroup *group);

NMA_AVAILABLE_IN_1_8_28
void nma_ws_fill_connection (NMAWs *self,
                             NMConnection *connection);

NMA_AVAILABLE_IN_1_8_28
void nma_ws_update_secrets (NMAWs *self,
                            NMConnection *connection);

NMA_AVAILABLE_IN_1_8_28
gboolean nma_ws_adhoc_compatible (NMAWs *self);

NMA_AVAILABLE_IN_1_8_28
gboolean nma_ws_hotspot_compatible (NMAWs *self);

G_END_DECLS

#include "nma-ws-802-1x.h"
#include "nma-ws-dynamic-wep.h"
#include "nma-ws-leap.h"
#include "nma-ws-owe.h"
#include "nma-ws-sae.h"
#include "nma-ws-wep-key.h"
#include "nma-ws-wpa-eap.h"
#include "nma-ws-wpa-psk.h"

#endif /* NMA_WS_H */
