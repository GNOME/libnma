// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_WS_DYNAMIC_WEP_H
#define NMA_WS_DYNAMIC_WEP_H

#include <glib.h>
#include <glib-object.h>
#include <NetworkManager.h>

#include "nma-version.h"

G_BEGIN_DECLS

typedef struct _NMAWsDynamicWep NMAWsDynamicWep;
typedef struct _NMAWsDynamicWepClass NMAWsDynamicWepClass;

#if defined(G_DEFINE_AUTOPTR_CLEANUP_FUNC) && NMA_VERSION_MIN_REQUIRED >= NMA_VERSION_1_10_6
G_DEFINE_AUTOPTR_CLEANUP_FUNC(NMAWsDynamicWep, g_object_unref)
#endif

#define NMA_TYPE_WS_DYNAMIC_WEP            (nma_ws_dynamic_wep_get_type ())
#define NMA_WS_DYNAMIC_WEP(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMA_TYPE_WS_SAE, NMAWsDynamicWep))
#define NMA_WS_DYNAMIC_WEP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMA_TYPE_WS_SAE, NMAWsDynamicWepClass))
#define NMA_IS_WS_DYNAMIC_WEP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMA_TYPE_WS_SAE))
#define NMA_IS_WS_DYNAMIC_WEP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMA_TYPE_WS_SAE))
#define NMA_WS_DYNAMIC_WEP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMA_TYPE_WS_SAE, NMAWsDynamicWepClass))

NMA_AVAILABLE_IN_1_8_28
GType nma_ws_dynamic_wep_get_type (void);

NMA_AVAILABLE_IN_1_8_28
NMAWsDynamicWep *nma_ws_dynamic_wep_new (NMConnection *connection,
                                         gboolean is_editor,
                                         gboolean secrets_only);

G_END_DECLS

#endif /* NMA_WS_DYNAMIC_WEP_H */
