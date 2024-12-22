// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright (C) 2007 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include "nma-eap.h"
#include "nma-ws.h"
#include "nma-ws-private.h"
#include "nma-ws-helpers.h"
#include "nma-ws-802-1x.h"
#include "nma-ws-802-1x-private.h"
#include "nma-ui-utils.h"
#include "utils.h"

struct _NMAEapLeap {
	NMAEap parent;

	NMAWs8021x *ws_8021x;

	gboolean editing_connection;

	const char *password_flags_name;
	GtkEntry *username_entry;
	GtkEntry *password_entry;
	GtkCheckButton *show_password;
};

static gboolean
validate (NMAEap *parent, GError **error)
{
	NMAEapLeap *method = (NMAEapLeap *)parent;
	const char *text;
	gboolean ret = TRUE;

	text = gtk_editable_get_text (GTK_EDITABLE (method->username_entry));
	if (!text || !*text) {
		widget_set_error (GTK_WIDGET (method->username_entry));
		g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("missing EAP-LEAP username"));
		ret = FALSE;
	} else
		widget_unset_error (GTK_WIDGET (method->username_entry));

	text = gtk_editable_get_text (GTK_EDITABLE (method->password_entry));
	if (!text || !*text) {
		widget_set_error (GTK_WIDGET (method->password_entry));
		if (ret) {
			g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("missing EAP-LEAP password"));
			ret = FALSE;
		}
	} else
		widget_unset_error (GTK_WIDGET (method->password_entry));

	return ret;
}

static void
add_to_size_group (NMAEap *parent, GtkSizeGroup *group)
{
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_leap_username_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_leap_password_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);
}

static void
fill_connection (NMAEap *parent, NMConnection *connection)
{
	NMAEapLeap *method = (NMAEapLeap *) parent;
	NMSetting8021x *s_8021x;
	NMSettingSecretFlags secret_flags;
	GtkWidget *passwd_entry;

	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);

	nm_setting_802_1x_add_eap_method (s_8021x, "leap");

	g_object_set (s_8021x,
	              NM_SETTING_802_1X_IDENTITY, gtk_editable_get_text (GTK_EDITABLE (method->username_entry)),
	              NM_SETTING_802_1X_PASSWORD, gtk_editable_get_text (GTK_EDITABLE (method->password_entry)),
	              NULL);

	passwd_entry = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_leap_password_entry"));
	g_assert (passwd_entry);

	/* Save 802.1X password flags to the connection */
	secret_flags = nma_utils_menu_to_secret_flags (passwd_entry);
	nm_setting_set_secret_flags (NM_SETTING (s_8021x), method->password_flags_name,
	                             secret_flags, NULL);

	/* Update secret flags and popup when editing the connection */
	if (method->editing_connection)
		nma_utils_update_password_storage (passwd_entry, secret_flags,
		                                   NM_SETTING (s_8021x), method->password_flags_name);
}

static void
update_secrets (NMAEap *parent, NMConnection *connection)
{
	nma_ws_helper_fill_secret_entry (connection,
	                                 GTK_EDITABLE (gtk_builder_get_object (parent->builder, "eap_leap_password_entry")),
	                                 NM_TYPE_SETTING_802_1X,
	                                 (HelperSecretFunc) nm_setting_802_1x_get_password);
}

/* Set the UI fields for user, password and show_password to the
 * values as provided by method->ws_8021x. */
static void
set_userpass_ui (NMAEapLeap *method)
{
	if (method->ws_8021x->username) {
		gtk_editable_set_text (GTK_EDITABLE (method->username_entry),
		                       method->ws_8021x->username);
	} else {
		gtk_editable_set_text (GTK_EDITABLE (method->username_entry), "");
	}

	if (method->ws_8021x->password && !method->ws_8021x->always_ask) {
		gtk_editable_set_text (GTK_EDITABLE (method->password_entry),
		                       method->ws_8021x->password);
	} else {
		gtk_editable_set_text (GTK_EDITABLE (method->password_entry), "");
	}

	gtk_check_button_set_active (method->show_password, method->ws_8021x->show_password);
}

static void
widgets_realized (GtkWidget *widget, NMAEapLeap *method)
{
	set_userpass_ui (method);
}

static void
widgets_unrealized (GtkWidget *widget, NMAEapLeap *method)
{
	nma_ws_802_1x_set_userpass (method->ws_8021x,
	                     gtk_editable_get_text (GTK_EDITABLE (method->username_entry)),
	                     gtk_editable_get_text (GTK_EDITABLE (method->password_entry)),
	                     (gboolean) -1,
	                     gtk_check_button_get_active (method->show_password));
}

static void
destroy (NMAEap *parent)
{
	NMAEapLeap *method = (NMAEapLeap *) parent;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_leap_grid"));
	g_assert (widget);
	g_signal_handlers_disconnect_by_data (widget, method);
}

NMAEapLeap *
nma_eap_leap_new (NMAWs8021x *ws_8021x,
                     NMConnection *connection,
                     gboolean secrets_only)
{
	NMAEapLeap *method;
	NMAEap *parent;
	GtkWidget *widget;
	NMSetting8021x *s_8021x = NULL;

	parent = nma_eap_init (NMA_WS (ws_8021x),
	                       sizeof (NMAEapLeap),
	                       validate,
	                       add_to_size_group,
	                       fill_connection,
	                       update_secrets,
	                       destroy,
	                       "/org/gnome/libnma/nma-eap-leap.ui",
	                       "eap_leap_grid",
	                       "eap_leap_username_entry",
	                       FALSE);
	if (!parent)
		return NULL;

	method = (NMAEapLeap *) parent;
	method->password_flags_name = NM_SETTING_802_1X_PASSWORD;
	method->editing_connection = secrets_only ? FALSE : TRUE;
	method->ws_8021x = ws_8021x;

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_leap_grid"));
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "realize",
	                  (GCallback) widgets_realized,
	                  method);
	g_signal_connect (G_OBJECT (widget), "unrealize",
	                  (GCallback) widgets_unrealized,
	                  method);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_leap_username_entry"));
	g_assert (widget);
	method->username_entry = GTK_ENTRY (widget);

	if (secrets_only)
		gtk_widget_set_sensitive (widget, FALSE);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_leap_password_entry"));
	g_assert (widget);
	method->password_entry = GTK_ENTRY (widget);

	/* Create password-storage popup menu for password entry under entry's secondary icon */
	if (connection)
		s_8021x = nm_connection_get_setting_802_1x (connection);
	nma_utils_setup_password_storage (widget, 0, (NMSetting *) s_8021x, method->password_flags_name,
	                                  FALSE, secrets_only);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "show_checkbutton_eapleap"));
	g_assert (widget);
	method->show_password = GTK_CHECK_BUTTON (widget);

	/* Initialize the UI fields with the security settings from method->ws_8021x.
	 * This will be done again when the widget gets realized. It must be done here as well,
	 * because the outer dialog will ask to 'validate' the connection before the security tab
	 * is shown/realized (to enable the 'Apply' button).
	 * As 'validate' accesses the contents of the UI fields, they must be initialized now, even
	 * if the widgets are not yet visible. */
	set_userpass_ui (method);

	return method;
}
