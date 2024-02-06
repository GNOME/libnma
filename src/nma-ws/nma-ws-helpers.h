// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2009 - 2019 Red Hat, Inc.
 */

#ifndef _NMA_WS_HELPERS_H_
#define _NMA_WS_HELPERS_H_


#include <gtk/gtk.h>
#include <glib.h>
#include <glib-object.h>
#include <NetworkManager.h>

typedef const char * (*HelperSecretFunc)(NMSetting *);

void nma_ws_helper_fill_secret_entry (NMConnection *connection,
                                      GtkEditable *entry,
                                      GType setting_type,
                                      HelperSecretFunc func);

#endif  /* _NMA_WS_HELPERS_H_ */
