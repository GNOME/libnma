// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_WS_H
#define NMA_WS_H

typedef struct _NMAWs NMAWs;
GType nma_ws_get_type (void);

#define NMA_TYPE_WS (nma_ws_get_type ())
#define NMA_WS(x) ((NMAWs *) x)

typedef void (*NMAWsChangedFunc) (NMAWs *sec, gpointer user_data);

typedef void (*NMAWsAddToSizeGroupFunc) (NMAWs *sec, GtkSizeGroup *group);
typedef void (*NMAWsFillConnectionFunc) (NMAWs *sec, NMConnection *connection);
typedef void (*NMAWsUpdateSecretsFunc)  (NMAWs *sec, NMConnection *connection);
typedef void (*NMAWsDestroyFunc)        (NMAWs *sec);
typedef gboolean (*NMAWsValidateFunc)   (NMAWs *sec, GError **error);
typedef GtkWidget * (*NMAWsNagUserFunc) (NMAWs *sec);

struct _NMAWs {
	guint32 refcount;
	gsize obj_size;
	GtkBuilder *builder;
	GtkWidget *ui_widget;
	NMAWsChangedFunc changed_notify;
	gpointer changed_notify_data;
	const char *default_field;
	gboolean adhoc_compatible;
	gboolean hotspot_compatible;

	char *username, *password;
	gboolean always_ask, show_password;

	NMAWsAddToSizeGroupFunc add_to_size_group;
	NMAWsFillConnectionFunc fill_connection;
	NMAWsUpdateSecretsFunc update_secrets;
	NMAWsValidateFunc validate;
	NMAWsDestroyFunc destroy;
};

GtkWidget *nma_ws_get_widget (NMAWs *sec);

void nma_ws_set_changed_notify (NMAWs *sec,
                                NMAWsChangedFunc func,
                                gpointer user_data);

gboolean nma_ws_validate (NMAWs *sec, GError **error);

void nma_ws_add_to_size_group (NMAWs *sec,
                               GtkSizeGroup *group);

void nma_ws_fill_connection (NMAWs *sec,
                             NMConnection *connection);

void nma_ws_update_secrets (NMAWs *sec,
                            NMConnection *connection);

gboolean nma_ws_adhoc_compatible (NMAWs *sec);

gboolean nma_ws_hotspot_compatible (NMAWs *sec);

void nma_ws_set_userpass (NMAWs *sec,
                          const char *user,
                          const char *password,
                          gboolean always_ask,
                          gboolean show_password);
void nma_ws_set_userpass_802_1x (NMAWs *sec,
                                 NMConnection *connection);

NMAWs *nma_ws_ref (NMAWs *sec);

void nma_ws_unref (NMAWs *sec);

/* Below for internal use only */

#include "nma-ws-sae.h"
#include "nma-ws-wep-key.h"
#include "nma-ws-wpa-psk.h"
#include "nma-ws-leap.h"
#include "nma-ws-wpa-eap.h"
#include "nma-ws-dynamic-wep.h"

NMAWs *nma_ws_init (gsize obj_size,
                    NMAWsValidateFunc validate,
                    NMAWsAddToSizeGroupFunc add_to_size_group,
                    NMAWsFillConnectionFunc fill_connection,
                    NMAWsUpdateSecretsFunc update_secrets,
                    NMAWsDestroyFunc destroy,
                    const char *ui_resource,
                    const char *ui_widget_name,
                    const char *default_field);

void nma_ws_changed_cb (GtkWidget *entry, gpointer user_data);

void nma_ws_clear_ciphers (NMConnection *connection);

#define AUTH_NAME_COLUMN   0
#define AUTH_METHOD_COLUMN 1

GtkWidget *nma_ws_802_1x_auth_combo_init (NMAWs *sec,
                                          const char *combo_name,
                                          const char *combo_label,
                                          GCallback auth_combo_changed_cb,
                                          NMConnection *connection,
                                          gboolean is_editor,
                                          gboolean secrets_only,
                                          const char *const*secrets_hints);

void nma_ws_802_1x_auth_combo_changed (GtkWidget *combo,
                                       NMAWs *sec,
                                       const char *vbox_name,
                                       GtkSizeGroup *size_group);

gboolean nma_ws_802_1x_validate (NMAWs *sec, const char *combo_name, GError **error);

void nma_ws_802_1x_add_to_size_group (NMAWs *sec,
                                      GtkSizeGroup *size_group,
                                      const char *label_name,
                                      const char *combo_name);

void nma_ws_802_1x_fill_connection (NMAWs *sec,
                                    const char *combo_name,
                                    NMConnection *connection);

void nma_ws_802_1x_update_secrets (NMAWs *sec,
                                   const char *combo_name,
                                   NMConnection *connection);

#endif /* NMA_WS_H */
