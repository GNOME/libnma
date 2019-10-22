// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef WS_WEP_KEY_H
#define WS_WEP_KEY_H

typedef struct _NMAWsWEPKey NMAWsWEPKey;

NMAWsWEPKey *nma_ws_wep_key_new (NMConnection *connection,
                                 NMWepKeyType type,
                                 gboolean adhoc_create,
                                 gboolean secrets_only);

#endif /* WS_WEP_KEY_H */
