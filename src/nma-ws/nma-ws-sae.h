// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_WS_SAE_H
#define NMA_WS_SAE_H

typedef struct _NMAWsSae NMAWsSae;

#define NMA_TYPE_WS_SAE            (nma_ws_sae_get_type ())
#define NMA_WS_SAE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMA_TYPE_WS_SAE, NMAWsSae))
#define NMA_WS_SAE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMA_TYPE_WS_SAE, NMAWsSaeClass))
#define NMA_IS_WS_SAE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMA_TYPE_WS_SAE))
#define NMA_IS_WS_SAE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMA_TYPE_WS_SAE))
#define NMA_WS_SAE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMA_TYPE_WS_SAE, NMAWsSaeClass))

GType nma_ws_sae_get_type (void);

NMAWsSae *nma_ws_sae_new (NMConnection *connection, gboolean secrets_only);

#endif /* NMA_WS_SAE_H */
