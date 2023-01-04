// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <gtk/gtk.h>
#include "nma-mobile-wizard.h"
#include "nma-mobile-providers.h"

#if !NM_CHECK_VERSION(1,36,0)
enum { NM_DEVICE_MODEM_CAPABILITY_5GNR=0x00000040 };
#endif


static void
wizard_cb (NMAMobileWizard *self, gboolean cancelled, NMAMobileWizardAccessMethod *method, gpointer user_data)
{
	GMainLoop *loop = user_data;

	if (cancelled)
		g_printerr ("Cancelled.\n");

	if (method) {
		g_printerr ("provider_name: '%s'\n", method->provider_name);
		g_printerr ("plan_name: '%s'\n", method->plan_name);
		g_printerr ("devtype:");
		if (method->devtype == NM_DEVICE_MODEM_CAPABILITY_NONE)
			g_printerr (" NONE");
		if (method->devtype & NM_DEVICE_MODEM_CAPABILITY_POTS)
			g_printerr (" POTS");
		if (method->devtype & NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO)
			g_printerr (" CDMA_EVDO");
		if (method->devtype & NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS)
			g_printerr (" GSM_UMTS");
		if (method->devtype & NM_DEVICE_MODEM_CAPABILITY_LTE)
			g_printerr (" LTE");
		if (method->devtype & NM_DEVICE_MODEM_CAPABILITY_5GNR)
			g_printerr (" 5GNR");
		g_printerr ("\n");
		g_printerr ("username: '%s'\n", method->username);
		g_printerr ("password: '%s'\n", method->password);
		g_printerr ("gsm_apn: '%s'\n", method->gsm_apn);
	}

	g_main_loop_quit (loop);
}

int
main (int argc, char *argv[])
{
	GMainLoop *loop;
	NMAMobileWizard *wizard;

	bindtextdomain (GETTEXT_PACKAGE, NMALOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	gtk_init ();
	loop = g_main_loop_new (NULL, FALSE);

	wizard = nma_mobile_wizard_new (NULL, NULL, NM_DEVICE_MODEM_CAPABILITY_NONE, TRUE, wizard_cb, loop);

	nma_mobile_wizard_present (wizard);
	g_main_loop_run (loop);
	nma_mobile_wizard_destroy (wizard);
	g_main_loop_unref (loop);
}
