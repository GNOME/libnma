// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <ctype.h>
#include <string.h>

#include "nma-ws.h"
#include "helpers.h"
#include "nma-ui-utils.h"
#include "utils.h"

#define WPA_PMK_LEN 32

struct _NMAWsWPAPSK {
	NMAWs parent;

	gboolean editing_connection;
	const char *password_flags_name;
};

static void
show_toggled_cb (GtkCheckButton *button, NMAWs *sec)
{
	GtkWidget *widget;
	gboolean visible;

	widget = GTK_WIDGET (gtk_builder_get_object (sec->builder, "wpa_psk_entry"));
	g_assert (widget);

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
}

static gboolean
validate (NMAWs *parent, GError **error)
{
	GtkWidget *entry;
	NMSettingSecretFlags secret_flags;
	const char *key;
	gsize len;
	int i;

	entry = GTK_WIDGET (gtk_builder_get_object (parent->builder, "wpa_psk_entry"));
	g_assert (entry);

	secret_flags = nma_utils_menu_to_secret_flags (entry);
	key = gtk_editable_get_text (GTK_EDITABLE (entry));
	len = key ? strlen (key) : 0;

        if (   secret_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED
            || secret_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED) {
		/* All good. */
	} else if ((len < 8) || (len > 64)) {
		widget_set_error (entry);
		g_set_error (error, NMA_ERROR, NMA_ERROR_GENERIC, _("invalid wpa-psk: invalid key-length %zu. Must be [8,63] bytes or 64 hex digits"), len);
		return FALSE;
	} else if (len == 64) {
		/* Hex PSK */
		for (i = 0; i < len; i++) {
			if (!isxdigit (key[i])) {
				widget_set_error (entry);
				g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("invalid wpa-psk: cannot interpret key with 64 bytes as hex"));
				return FALSE;
			}
		}
	}
	widget_unset_error (entry);

	/* passphrase can be between 8 and 63 characters inclusive */

	return TRUE;
}

static void
add_to_size_group (NMAWs *parent, GtkSizeGroup *group)
{
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "wpa_psk_type_label"));
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "wpa_psk_label"));
	gtk_size_group_add_widget (group, widget);
}

static void
fill_connection (NMAWs *parent, NMConnection *connection)
{
	NMAWsWPAPSK *wpa_psk = (NMAWsWPAPSK *) parent;
	GtkWidget *widget, *passwd_entry;
	const char *key;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wireless_sec;
	NMSettingSecretFlags secret_flags;
	const char *mode;
	gboolean is_adhoc = FALSE;

	s_wireless = nm_connection_get_setting_wireless (connection);
	g_assert (s_wireless);

	mode = nm_setting_wireless_get_mode (s_wireless);
	if (mode && !strcmp (mode, "adhoc"))
		is_adhoc = TRUE;

	/* Blow away the old security setting by adding a clear one */
	s_wireless_sec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, (NMSetting *) s_wireless_sec);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "wpa_psk_entry"));
	passwd_entry = widget;
	key = gtk_editable_get_text (GTK_EDITABLE (widget));
	g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_PSK, key, NULL);

	/* Save PSK_FLAGS to the connection */
	secret_flags = nma_utils_menu_to_secret_flags (passwd_entry);
	nm_setting_set_secret_flags (NM_SETTING (s_wireless_sec), NM_SETTING_WIRELESS_SECURITY_PSK,
	                             secret_flags, NULL);

	/* Update secret flags and popup when editing the connection */
	if (wpa_psk->editing_connection)
		nma_utils_update_password_storage (passwd_entry, secret_flags,
		                                   NM_SETTING (s_wireless_sec), wpa_psk->password_flags_name);

	nma_ws_clear_ciphers (connection);
	if (is_adhoc) {
		/* Ad-Hoc settings as specified by the supplicant */
		g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", NULL);
		nm_setting_wireless_security_add_proto (s_wireless_sec, "rsn");
		nm_setting_wireless_security_add_pairwise (s_wireless_sec, "ccmp");
		nm_setting_wireless_security_add_group (s_wireless_sec, "ccmp");
	} else {
		g_object_set (s_wireless_sec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", NULL);

		/* Just leave ciphers and protocol empty, the supplicant will
		 * figure that out magically based on the AP IEs and card capabilities.
		 */
	}
}

static void
update_secrets (NMAWs *parent, NMConnection *connection)
{
	helper_fill_secret_entry (connection,
	                          parent->builder,
	                          "wpa_psk_entry",
	                          NM_TYPE_SETTING_WIRELESS_SECURITY,
	                          (HelperSecretFunc) nm_setting_wireless_security_get_psk);
}

NMAWsWPAPSK *
nma_ws_wpa_psk_new (NMConnection *connection, gboolean secrets_only)
{
	NMAWs *parent;
	NMAWsWPAPSK *sec;
	NMSetting *setting = NULL;
	GtkWidget *widget;

	parent = nma_ws_init (sizeof (NMAWsWPAPSK),
	                      validate,
	                      add_to_size_group,
	                      fill_connection,
	                      update_secrets,
	                      NULL,
	                      "/org/gnome/libnma/nma-ws-wpa-psk.ui",
	                      "wpa_psk_notebook",
	                      "wpa_psk_entry");
	if (!parent)
		return NULL;

	parent->adhoc_compatible = TRUE;
	sec = (NMAWsWPAPSK *) parent;
	sec->editing_connection = secrets_only ? FALSE : TRUE;
	sec->password_flags_name = NM_SETTING_WIRELESS_SECURITY_PSK;

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "wpa_psk_entry"));
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "changed",
	                  (GCallback) nma_ws_changed_cb,
	                  sec);
	gtk_editable_set_width_chars (GTK_EDITABLE (widget), 28);

	/* Create password-storage popup menu for password entry under entry's secondary icon */
	if (connection)
		setting = (NMSetting *) nm_connection_get_setting_wireless_security (connection);
	nma_utils_setup_password_storage (widget, 0, setting, sec->password_flags_name,
	                                  FALSE, secrets_only);

	/* Fill secrets, if any */
	if (connection)
		update_secrets (NMA_WS (sec), connection);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "show_checkbutton_wpa"));
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "toggled",
	                  (GCallback) show_toggled_cb,
	                  sec);

	/* Hide WPA/RSN for now since this can be autodetected by NM and the
	 * supplicant when connecting to the AP.
	 */

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "wpa_psk_type_combo"));
	g_assert (widget);
	gtk_widget_hide (widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "wpa_psk_type_label"));
	g_assert (widget);
	gtk_widget_hide (widget);

	return sec;
}
