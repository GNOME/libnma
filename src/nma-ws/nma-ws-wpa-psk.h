// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef WS_WPA_PSK_H
#define WS_WPA_PSK_H

typedef struct _NMAWsWPAPSK NMAWsWPAPSK;

NMAWsWPAPSK *nma_ws_wpa_psk_new (NMConnection *connection, gboolean secrets_only);

#endif /* WS_WEP_KEY_H */
