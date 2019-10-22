// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_EAP_PEAP_H
#define NMA_EAP_PEAP_H

#include "nma-ws.h"

typedef struct _NMAEapPEAP NMAEapPEAP;

NMAEapPEAP *nma_eap_peap_new (NMAWs *ws_parent,
                              NMConnection *connection,
                              gboolean is_editor,
                              gboolean secrets_only);

#endif /* NMA_EAP_PEAP_H */
