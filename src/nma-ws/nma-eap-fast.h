// SPDX-License-Identifier: GPL-2.0+
/*
 * EAP-FAST authentication method (RFC4851)
 *
 * Copyright 2012 - 2019 Red Hat, Inc.
 */

#ifndef NMA_EAP_FAST_H
#define NMA_EAP_FAST_H

#include "nma-ws.h"

typedef struct _NMAEapFAST NMAEapFAST;

NMAEapFAST *nma_eap_fast_new (NMAWs *ws_parent,
                              NMConnection *connection,
                              gboolean is_editor,
                              gboolean secrets_only);

#endif /* NMA_EAP_FAST_H */

