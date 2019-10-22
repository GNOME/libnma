// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef WS_WPA_EAP_H
#define WS_WPA_EAP_H

typedef struct _NMAWsWPAEAP NMAWsWPAEAP;

NMAWsWPAEAP *nma_ws_wpa_eap_new (NMConnection *connection,
                                 gboolean is_editor,
                                 gboolean secrets_only,
                                 const char *const*secrets_hints);

#endif /* WS_WPA_EAP_H */
