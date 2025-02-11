// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_EAP_LEAP_H
#define NMA_EAP_LEAP_H

#if !defined(NMA_COMPILATION)
#error "This is an internal header, available only when building libnma."
#endif

#include <glib.h>
#include <NetworkManager.h>

#include "nma-ws.h"

typedef struct _NMAEapLeap NMAEapLeap;

NMAEapLeap *nma_eap_leap_new (NMAWs8021x *ws_8021x,
                              NMConnection *connection,
                              gboolean secrets_only);

#endif /* NMA_EAP_LEAP_H */
