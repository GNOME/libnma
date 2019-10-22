// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef WS_DYNAMIC_WEP_H
#define WS_DYNAMIC_WEP_H

typedef struct _NMAWsDynamicWEP NMAWsDynamicWEP;

NMAWsDynamicWEP *nma_ws_dynamic_wep_new (NMConnection *connection,
                                         gboolean is_editor,
                                         gboolean secrets_only);

#endif /* WS_DYNAMIC_WEP_H */
