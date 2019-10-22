// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef WS_LEAP_H
#define WS_LEAP_H

typedef struct _NMAWsLEAP NMAWsLEAP;

NMAWsLEAP *nma_ws_leap_new (NMConnection *connection, gboolean secrets_only);

#endif /* WS_LEAP_H */
