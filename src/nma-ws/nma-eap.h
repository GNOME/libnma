// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_EAP_H
#define NMA_EAP_H

#if !defined(NMA_COMPILATION)
#error "This is an internal header, available only when building libnma."
#endif

#include <gtk/gtk.h>
#include <glib.h>
#include <glib-object.h>
#include <NetworkManager.h>

typedef struct _NMAEap NMAEap;

typedef void        (*NMAEapAddToSizeGroupFunc) (NMAEap *method, GtkSizeGroup *group);
typedef void        (*NMAEapFillConnectionFunc) (NMAEap *method, NMConnection *connection);
typedef void        (*NMAEapUpdateSecretsFunc)  (NMAEap *method, NMConnection *connection);
typedef void        (*NMAEapDestroyFunc)        (NMAEap *method);
typedef gboolean    (*NMAEapValidateFunc)       (NMAEap *method, GError **error);

struct _NMAEap {
	guint32 refcount;
	gsize obj_size;

	GtkBuilder *builder;
	GtkWidget *ui_widget;

	const char *default_field;

	gboolean phase2;
	gboolean secrets_only;

	NMAEapAddToSizeGroupFunc add_to_size_group;
	NMAEapFillConnectionFunc fill_connection;
	NMAEapUpdateSecretsFunc update_secrets;
	NMAEapValidateFunc validate;
	NMAEapDestroyFunc destroy;
};

#define NMA_EAP(x) ((NMAEap *) x)


GtkWidget *nma_eap_get_widget (NMAEap *method);

gboolean nma_eap_validate (NMAEap *method, GError **error);

void nma_eap_add_to_size_group (NMAEap *method, GtkSizeGroup *group);

void nma_eap_fill_connection (NMAEap *method,
                              NMConnection *connection);

void nma_eap_update_secrets (NMAEap *method, NMConnection *connection);

NMAEap *nma_eap_ref (NMAEap *method);

void nma_eap_unref (NMAEap *method);

GType nma_eap_get_type (void);

/* Below for internal use only */

#include "nma-cert-chooser.h"
#include "nma-eap-tls.h"
#include "nma-eap-leap.h"
#include "nma-eap-fast.h"
#include "nma-eap-ttls.h"
#include "nma-eap-peap.h"
#include "nma-eap-simple.h"

NMAEap *nma_eap_init (NMAWs *ws,
                      gsize obj_size,
                      NMAEapValidateFunc validate,
                      NMAEapAddToSizeGroupFunc add_to_size_group,
                      NMAEapFillConnectionFunc fill_connection,
                      NMAEapUpdateSecretsFunc update_secrets,
                      NMAEapDestroyFunc destroy,
                      const char *ui_resource,
                      const char *ui_widget_name,
                      const char *default_field,
                      gboolean phase2);

void nma_eap_phase2_update_secrets_helper (NMAEap *method,
                                           NMConnection *connection,
                                           const char *combo_name,
                                           guint32 column);

void nma_eap_ca_cert_ignore_set (NMAEap *method,
                                 NMConnection *connection,
                                 const char *filename,
                                 gboolean ca_cert_error);
gboolean nma_eap_ca_cert_ignore_get (NMAEap *method, NMConnection *connection);

void nma_eap_ca_cert_ignore_save (NMConnection *connection);
void nma_eap_ca_cert_ignore_load (NMConnection *connection);

GError *nma_eap_ca_cert_validate_cb (NMACertChooser *cert_chooser, gpointer user_data);

void nma_eap_setup_cert_chooser (NMACertChooser *cert_chooser,
                                 NMSetting8021x *s_8021x,
                                 NMSetting8021xCKScheme (*cert_scheme_func) (NMSetting8021x *setting),
                                 const char *(*cert_path_func) (NMSetting8021x *setting),
                                 const char *(*cert_uri_func) (NMSetting8021x *setting),
                                 const char *(*cert_password_func) (NMSetting8021x *setting),
                                 NMSetting8021xCKScheme (*key_scheme_func) (NMSetting8021x *setting),
                                 const char *(*key_path_func) (NMSetting8021x *setting),
                                 const char *(*key_uri_func) (NMSetting8021x *setting),
                                 const char *(*key_password_func) (NMSetting8021x *setting));

#endif /* NMA_EAP_H */
