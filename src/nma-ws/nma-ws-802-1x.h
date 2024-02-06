// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_WS_802_1X_H
#define NMA_WS_802_1X_H

#include <glib.h>
#include <glib-object.h>

#include <NetworkManager.h>

#include "nma-version.h"

G_BEGIN_DECLS

typedef struct _NMAWs8021x NMAWs8021x;
typedef struct _NMAWs8021xClass NMAWs8021xClass;

#if defined(G_DEFINE_AUTOPTR_CLEANUP_FUNC) && NMA_VERSION_MIN_REQUIRED >= NMA_VERSION_1_10_6
G_DEFINE_AUTOPTR_CLEANUP_FUNC(NMAWs8021x, g_object_unref)
#endif

#define NMA_TYPE_WS_802_1X            (nma_ws_802_1x_get_type ())
#define NMA_WS_802_1X(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMA_TYPE_WS_802_1X, NMAWs8021x))
#define NMA_WS_802_1X_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMA_TYPE_WS_802_1X, NMAWs8021xClass))
#define NMA_IS_WS_802_1X(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMA_TYPE_WS_802_1X))
#define NMA_IS_WS_802_1X_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMA_TYPE_WS_802_1X))
#define NMA_WS_802_1X_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMA_TYPE_WS_802_1X, NMAWs8021xClass))

NMA_AVAILABLE_IN_1_8_28
GType nma_ws_802_1x_get_type (void);

NMA_AVAILABLE_IN_1_8_28
NMAWs8021x *nma_ws_802_1x_new (NMConnection *connection,
                               gboolean is_editor,
                               gboolean secrets_only);

G_END_DECLS

#endif /* NMA_WS_802_1X_H */
