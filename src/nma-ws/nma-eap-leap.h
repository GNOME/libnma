// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_EAP_LEAP_H
#define NMA_EAP_LEAP_H

#include "nma-ws.h"

typedef struct _NMAEapLEAP NMAEapLEAP;

NMAEapLEAP *nma_eap_leap_new (NMAWs *ws_parent,
                              NMConnection *connection,
                              gboolean secrets_only);

#endif /* NMA_EAP_LEAP_H */
