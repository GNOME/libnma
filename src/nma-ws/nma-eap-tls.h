// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_EAP_TLS_H
#define NMA_EAP_TLS_H

#include "nma-ws.h"

typedef struct _NMAEapTLS NMAEapTLS;

NMAEapTLS *nma_eap_tls_new (NMAWs *ws_parent,
                            NMConnection *connection,
                            gboolean phase2,
                            gboolean secrets_only);

#endif /* NMA_EAP_TLS_H */
