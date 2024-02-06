// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_WS_WEP_KEY_H
#define NMA_WS_WEP_KEY_H

#include <glib.h>
#include <glib-object.h>
#include <NetworkManager.h>

#include "nma-version.h"

G_BEGIN_DECLS

typedef struct _NMAWsWepKey NMAWsWepKey;
typedef struct _NMAWsWepKeyClass NMAWsWepKeyClass;

#if defined(G_DEFINE_AUTOPTR_CLEANUP_FUNC) && NMA_VERSION_MIN_REQUIRED >= NMA_VERSION_1_10_6
G_DEFINE_AUTOPTR_CLEANUP_FUNC(NMAWsWepKey, g_object_unref)
#endif

#define NMA_TYPE_WS_WEP_KEY            (nma_ws_wep_key_get_type ())
#define NMA_WS_WEP_KEY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMA_TYPE_WS_WEP_KEY, NMAWsWepKey))
#define NMA_WS_WEP_KEY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMA_TYPE_WS_WEP_KEY, NMAWsWepKeyClass))
#define NMA_IS_WS_WEP_KEY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMA_TYPE_WS_WEP_KEY))
#define NMA_IS_WS_WEP_KEY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMA_TYPE_WS_WEP_KEY))
#define NMA_WS_WEP_KEY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMA_TYPE_WS_WEP_KEY, NMAWsWepKeyClass))

NMA_AVAILABLE_IN_1_8_28
GType nma_ws_wep_key_get_type (void);

NMA_AVAILABLE_IN_1_8_28
NMAWsWepKey *nma_ws_wep_key_new (NMConnection *connection,
                                 NMWepKeyType type,
                                 gboolean adhoc_create,
                                 gboolean secrets_only);

G_END_DECLS

#endif /* NMA_WS_WEP_KEY_H */
