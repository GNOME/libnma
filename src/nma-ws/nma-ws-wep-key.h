// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_WS_WEP_KEY_H
#define NMA_WS_WEP_KEY_H

typedef struct _NMAWsWepKey NMAWsWepKey;

#define NMA_TYPE_WS_WEP_KEY            (nma_ws_wep_key_get_type ())
#define NMA_WS_WEP_KEY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMA_TYPE_WS_WEP_KEY, NMAWsWepKey))
#define NMA_WS_WEP_KEY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMA_TYPE_WS_WEP_KEY, NMAWsWepKeyClass))
#define NMA_IS_WS_WEP_KEY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMA_TYPE_WS_WEP_KEY))
#define NMA_IS_WS_WEP_KEY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMA_TYPE_WS_WEP_KEY))
#define NMA_WS_WEP_KEY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMA_TYPE_WS_WEP_KEY, NMAWsWepKeyClass))

GType nma_ws_wep_key_get_type (void);

NMAWsWepKey *nma_ws_wep_key_new (NMConnection *connection,
                                 NMWepKeyType type,
                                 gboolean adhoc_create,
                                 gboolean secrets_only);

#endif /* NMA_WS_WEP_KEY_H */
