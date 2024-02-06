// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_WS_SAE_H
#define NMA_WS_SAE_H

#include <glib.h>
#include <glib-object.h>

#include <NetworkManager.h>

#include "nma-version.h"

G_BEGIN_DECLS

typedef struct _NMAWsSae NMAWsSae;
typedef struct _NMAWsSaeClass NMAWsSaeClass;

#if defined(G_DEFINE_AUTOPTR_CLEANUP_FUNC) && NMA_VERSION_MIN_REQUIRED >= NMA_VERSION_1_10_6
G_DEFINE_AUTOPTR_CLEANUP_FUNC(NMAWsSae, g_object_unref)
#endif

#define NMA_TYPE_WS_SAE            (nma_ws_sae_get_type ())
#define NMA_WS_SAE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMA_TYPE_WS_SAE, NMAWsSae))
#define NMA_WS_SAE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMA_TYPE_WS_SAE, NMAWsSaeClass))
#define NMA_IS_WS_SAE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMA_TYPE_WS_SAE))
#define NMA_IS_WS_SAE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMA_TYPE_WS_SAE))
#define NMA_WS_SAE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMA_TYPE_WS_SAE, NMAWsSaeClass))

NMA_AVAILABLE_IN_1_8_28
GType nma_ws_sae_get_type (void);

NMA_AVAILABLE_IN_1_8_28
NMAWsSae *nma_ws_sae_new (NMConnection *connection, gboolean secrets_only);

G_END_DECLS

#endif /* NMA_WS_SAE_H */
