// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_WS_WPA_PSK_H
#define NMA_WS_WPA_PSK_H

#include "nma-version.h"

G_BEGIN_DECLS

typedef struct _NMAWsWpaPsk NMAWsWpaPsk;
typedef struct _NMAWsWpaPskClass NMAWsWpaPskClass;

#if defined(G_DEFINE_AUTOPTR_CLEANUP_FUNC) && NMA_VERSION_MIN_REQUIRED >= NMA_VERSION_1_10_6
G_DEFINE_AUTOPTR_CLEANUP_FUNC(NMAWsWpaPsk, g_object_unref)
#endif

#define NMA_TYPE_WS_WPA_PSK            (nma_ws_wpa_psk_get_type ())
#define NMA_WS_WPA_PSK(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMA_TYPE_WS_WPA_PSK, NMAWsWpaPsk))
#define NMA_WS_WPA_PSK_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMA_TYPE_WS_WPA_PSK, NMAWsWpaPskClass))
#define NMA_IS_WS_WPA_PSK(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMA_TYPE_WS_WPA_PSK))
#define NMA_IS_WS_WPA_PSK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMA_TYPE_WS_WPA_PSK))
#define NMA_WS_WPA_PSK_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMA_TYPE_WS_WPA_PSK, NMAWsWpaPskClass))

NMA_AVAILABLE_IN_1_8_28
GType nma_ws_wpa_psk_get_type (void);

NMA_AVAILABLE_IN_1_8_28
NMAWsWpaPsk *nma_ws_wpa_psk_new (NMConnection *connection, gboolean secrets_only);

G_END_DECLS

#endif /* NMA_WS_WPA_PSK_H */
