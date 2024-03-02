// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager Connection editor -- Connection editor for NetworkManager
 *
 * Dan Williams <dcbw@redhat.com>
 * Lubomir Rintel <lkundrak@v3.sk>
 *
 * (C) Copyright 2008 - 2018 Red Hat, Inc.
 */

#ifndef __NMA_MOBILE_WIZARD_H__
#define __NMA_MOBILE_WIZARD_H__

#include <glib.h>
#include <gtk/gtk.h>
#include <NetworkManager.h>
#include <nm-device.h>

#include "nma-version.h"

typedef struct _NMAMobileWizard NMAMobileWizard;
typedef struct _NMAMobileWizardClass NMAMobileWizardClass;

#if defined(G_DEFINE_AUTOPTR_CLEANUP_FUNC) && NMA_VERSION_MIN_REQUIRED >= NMA_VERSION_1_10_6
G_DEFINE_AUTOPTR_CLEANUP_FUNC(NMAMobileWizard, g_object_unref)
#endif

/**
 * NMAMobileWizardAccessMethod:
 * @provider_name: The mobile network provider name
 * @plan_name: The provided network access billing plan
 * @devtype: Required NetworkManager device capabilities
 * @username: User login
 * @password: User secret
 * @gsm_apn: The GSM Access Point Name
 *
 * Network access method details.
 */
typedef struct {
	char *provider_name;
	char *plan_name;
	NMDeviceModemCapabilities devtype;
	char *username;
	char *password;
	char *gsm_apn;
} NMAMobileWizardAccessMethod;

typedef void (*NMAMobileWizardCallback) (NMAMobileWizard *self,
                                         gboolean canceled,
                                         NMAMobileWizardAccessMethod *method,
                                         gpointer user_data);

#define NMA_TYPE_MOBILE_WIZARD            (nma_mobile_wizard_get_type ())
#define NMA_MOBILE_WIZARD(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMA_TYPE_MOBILE_WIZARD, NMAMobileWizard))
#define NMA_MOBILE_WIZARD_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMA_TYPE_MOBILE_WIZARD, NMAMobileWizardClass))
#define NMA_IS_MOBILE_WIZARD(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMA_TYPE_MOBILE_WIZARD))
#define NMA_IS_MOBILE_WIZARD_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMA_TYPE_MOBILE_WIZARD))
#define NMA_MOBILE_WIZARD_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMA_TYPE_MOBILE_WIZARD, NMAMobileWizardClass))

GType nma_mobile_wizard_get_type (void);

NMAMobileWizard *nma_mobile_wizard_new (GtkWindow *parent,
                                        GtkWindowGroup *window_group,
                                        NMDeviceModemCapabilities modem_caps,
                                        gboolean will_connect_after,
                                        NMAMobileWizardCallback cb,
                                        gpointer user_data);

void nma_mobile_wizard_present (NMAMobileWizard *wizard);

void nma_mobile_wizard_destroy (NMAMobileWizard *self);

#endif /* __NMA_MOBILE_WIZARD_H__ */
