// SPDX-License-Identifier: GPL-2.0+
/*
 * EAP-FAST authentication method (RFC4851)
 *
 * Copyright 2012 - 2019 Red Hat, Inc.
 */

#ifndef NMA_EAP_FAST_H
#define NMA_EAP_FAST_H

#if !defined(NMA_COMPILATION)
#error "This is an internal header, available only when building libnma."
#endif

#include <glib.h>
#include <NetworkManager.h>

#include "nma-ws.h"

typedef struct _NMAEapFast NMAEapFast;

NMAEapFast *nma_eap_fast_new (NMAWs8021x *ws_8021x,
                              NMConnection *connection,
                              gboolean is_editor,
                              gboolean secrets_only);

#endif /* NMA_EAP_FAST_H */
