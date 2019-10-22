// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2009 - 2019 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"
#include "nma-ws-helpers.h"

void
nma_ws_helper_fill_secret_entry (NMConnection *connection,
                                 GtkEditable *entry,
                                 GType setting_type,
                                 HelperSecretFunc func)
{
	NMSetting *setting;
	const char *tmp;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (entry != NULL);
	g_return_if_fail (func != NULL);

	setting = nm_connection_get_setting (connection, setting_type);
	if (setting) {
		tmp = (*func) (setting);
		if (tmp)
			gtk_editable_set_text (entry, tmp);
	}
}
