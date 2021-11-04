// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <gtk/gtk.h>
#include "nma-vpn-password-dialog.h"

int
main (int argc, char *argv[])
{
	GtkWidget *dialog;

	gtk_init ();

	dialog = nma_vpn_password_dialog_new ("Title", "Message", "Password");

	nma_vpn_password_dialog_set_password (NMA_VPN_PASSWORD_DIALOG (dialog), "Password One");
	nma_vpn_password_dialog_set_password_label (NMA_VPN_PASSWORD_DIALOG (dialog), "First _Label");

	nma_vpn_password_dialog_set_password_secondary (NMA_VPN_PASSWORD_DIALOG (dialog), "");
	nma_vpn_password_dialog_set_password_secondary_label (NMA_VPN_PASSWORD_DIALOG (dialog), "_Second Label");
	nma_vpn_password_dialog_set_show_password_secondary (NMA_VPN_PASSWORD_DIALOG (dialog), TRUE);

	nma_vpn_password_dialog_set_password_ternary_label (NMA_VPN_PASSWORD_DIALOG (dialog), "_Third Label");
	nma_vpn_password_dialog_set_show_password_ternary (NMA_VPN_PASSWORD_DIALOG (dialog), TRUE);

	nma_vpn_password_dialog_run_and_block (NMA_VPN_PASSWORD_DIALOG (dialog));
	gtk_window_destroy (GTK_WINDOW (dialog));
}
