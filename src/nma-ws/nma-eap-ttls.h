// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_EAP_TTLS_H
#define NMA_EAP_TTLS_H

#include "nma-ws.h"

typedef struct _NMAEapTTLS NMAEapTTLS;

NMAEapTTLS *nma_eap_ttls_new (NMAWs *ws_parent,
                              NMConnection *connection,
                              gboolean is_editor,
                              gboolean secrets_only);

#endif /* NMA_EAP_TLS_H */
