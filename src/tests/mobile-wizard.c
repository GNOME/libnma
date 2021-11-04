// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <gtk/gtk.h>
#include "nma-mobile-wizard.h"

static void
wizard_cb (NMAMobileWizard *self, gboolean canceled, NMAMobileWizardAccessMethod *method, gpointer user_data)
{
	GMainLoop *loop = user_data;

	g_main_loop_quit (loop);
}

int
main (int argc, char *argv[])
{
	GMainLoop *loop;
	NMAMobileWizard *wizard;

	gtk_init ();
	loop = g_main_loop_new (NULL, FALSE);

	wizard = nma_mobile_wizard_new (NULL, NULL, NM_DEVICE_MODEM_CAPABILITY_NONE, TRUE, wizard_cb, loop);

	nma_mobile_wizard_present (wizard);
	g_main_loop_run (loop);
	nma_mobile_wizard_destroy (wizard);
	g_main_loop_unref (loop);
}
