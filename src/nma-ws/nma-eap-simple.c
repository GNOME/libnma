// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright (C) 2007 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <string.h>

#include "nma-eap.h"
#include "nma-ws.h"
#include "nma-ws-private.h"
#include "nma-ws-helpers.h"
#include "nma-ws-802-1x.h"
#include "nma-ws-802-1x-private.h"
#include "nma-ui-utils.h"
#include "utils.h"

struct _NMAEapSimple {
	NMAEap parent;

	NMAWs8021x *ws_8021x;

	const char *password_flags_name;
	NMAEapSimpleType type;
	NMAEapSimpleFlags flags;

	gboolean username_requested;
	gboolean password_requested;
	gboolean pkey_passphrase_requested;
	GtkEntry *username_entry;
	GtkEntry *password_entry;
	GtkCheckButton *show_password;
	GtkEntry *pkey_passphrase_entry;
	guint idle_func_id;
};

static gboolean
always_ask_selected (GtkEntry *passwd_entry)
{
	return !!(  nma_utils_menu_to_secret_flags (GTK_WIDGET (passwd_entry))
	          & NM_SETTING_SECRET_FLAG_NOT_SAVED);
}

static gboolean
validate (NMAEap *parent, GError **error)
{
	NMAEapSimple *method = (NMAEapSimple *)parent;
	const char *text;
	gboolean ret = TRUE;

	if (method->username_requested) {
		text = gtk_editable_get_text (GTK_EDITABLE (method->username_entry));
		if (!text || !*text) {
			widget_set_error (GTK_WIDGET (method->username_entry));
			g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("missing EAP username"));
			ret = FALSE;
		} else
			widget_unset_error (GTK_WIDGET (method->username_entry));
	}

	/* Check if the password should always be requested */
	if (method->password_requested) {
		if (always_ask_selected (method->password_entry))
			widget_unset_error (GTK_WIDGET (method->password_entry));
		else {
			text = gtk_editable_get_text (GTK_EDITABLE (method->password_entry));
			if (!text || !*text) {
				widget_set_error (GTK_WIDGET (method->password_entry));
				if (ret) {
					g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC,
					                     _("missing EAP password"));
					ret = FALSE;
				}
			} else
				widget_unset_error (GTK_WIDGET (method->password_entry));
		}
	}

	if (method->pkey_passphrase_requested) {
		text = gtk_editable_get_text (GTK_EDITABLE (method->pkey_passphrase_entry));
		if (!text || !*text) {
			widget_set_error (GTK_WIDGET (method->pkey_passphrase_entry));
			if (ret) {
				g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC,
				                     _("missing EAP client Private Key passphrase"));
				ret = FALSE;
			}
		} else
			widget_unset_error (GTK_WIDGET (method->pkey_passphrase_entry));
	}

	return ret;
}

static void
add_to_size_group (NMAEap *parent, GtkSizeGroup *group)
{
	NMAEapSimple *method = (NMAEapSimple *) parent;
	GtkWidget *widget;

	if (method->username_requested) {
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_simple_username_label"));
		g_assert (widget);
		gtk_size_group_add_widget (group, widget);
	}

	if (method->password_requested) {
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_simple_password_label"));
		g_assert (widget);
		gtk_size_group_add_widget (group, widget);
	}

	if (method->pkey_passphrase_requested) {
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_simple_pkey_passphrase_label"));
		g_assert (widget);
		gtk_size_group_add_widget (group, widget);
	}
}

typedef struct {
	const char *name;
	gboolean autheap_allowed;
} EapType;

/* Indexed by NMA_EAP_SIMPLE_TYPE_* */
static const EapType eap_table[NMA_EAP_SIMPLE_TYPE_LAST] = {
	[NMA_EAP_SIMPLE_TYPE_PAP]             = { "pap",      FALSE },
	[NMA_EAP_SIMPLE_TYPE_MSCHAP]          = { "mschap",   FALSE },
	[NMA_EAP_SIMPLE_TYPE_MSCHAP_V2]       = { "mschapv2", TRUE  },
	[NMA_EAP_SIMPLE_TYPE_PLAIN_MSCHAP_V2] = { "mschapv2", FALSE },
	[NMA_EAP_SIMPLE_TYPE_MD5]             = { "md5",      TRUE  },
	[NMA_EAP_SIMPLE_TYPE_PWD]             = { "pwd",      TRUE  },
	[NMA_EAP_SIMPLE_TYPE_CHAP]            = { "chap",     FALSE },
	[NMA_EAP_SIMPLE_TYPE_GTC]             = { "gtc",      TRUE  },
	[NMA_EAP_SIMPLE_TYPE_UNKNOWN]         = { "unknown",  TRUE  },
};

static void
fill_connection (NMAEap *parent, NMConnection *connection)
{
	NMAEapSimple *method = (NMAEapSimple *) parent;
	NMSetting8021x *s_8021x;
	gboolean not_saved = FALSE;
	NMSettingSecretFlags flags;
	const EapType *eap_type;

	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);

	if (!(method->flags & NMA_EAP_SIMPLE_FLAG_SECRETS_ONLY)) {
		/* If this is the main EAP method, clear any existing methods because the
		 * user-selected one will replace it.
		 */
		if (parent->phase2 == FALSE)
			nm_setting_802_1x_clear_eap_methods (s_8021x);

		eap_type = &eap_table[method->type];
		if (parent->phase2) {
			/* If the outer EAP method (TLS, TTLS, PEAP, etc) allows inner/phase2
			 * EAP methods (which only TTLS allows) *and* the inner/phase2 method
			 * supports being an inner EAP method, then set PHASE2_AUTHEAP.
			 * Otherwise the inner/phase2 method goes into PHASE2_AUTH.
			 */
			if ((method->flags & NMA_EAP_SIMPLE_FLAG_AUTHEAP_ALLOWED) && eap_type->autheap_allowed) {
				g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTHEAP, eap_type->name, NULL);
				g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTH, NULL, NULL);
			} else {
				g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTH, eap_type->name, NULL);
				g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTHEAP, NULL, NULL);
			}
		} else
			nm_setting_802_1x_add_eap_method (s_8021x, eap_type->name);
	}

	if (method->username_requested) {
		g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY,
		              gtk_editable_get_text (GTK_EDITABLE (method->username_entry)),
		              NULL);
	}

	if (method->password_requested) {
		/* Save the password always ask setting */
		not_saved = always_ask_selected (method->password_entry);
		flags = nma_utils_menu_to_secret_flags (GTK_WIDGET (method->password_entry));
		nm_setting_set_secret_flags (NM_SETTING (s_8021x), method->password_flags_name, flags, NULL);

		/* Fill the connection's password if we're in the applet so that it'll get
		 * back to NM.  From the editor though, since the connection isn't going
		 * back to NM in response to a GetSecrets() call, we don't save it if the
		 * user checked "Always Ask".
		 */
		if (!(method->flags & NMA_EAP_SIMPLE_FLAG_IS_EDITOR) || not_saved == FALSE) {
			g_object_set (s_8021x, NM_SETTING_802_1X_PASSWORD,
			              gtk_editable_get_text (GTK_EDITABLE (method->password_entry)),
			              NULL);
		}

		/* Update secret flags and popup when editing the connection */
		if (!(method->flags & NMA_EAP_SIMPLE_FLAG_SECRETS_ONLY)) {
			GtkWidget *passwd_entry = GTK_WIDGET (gtk_builder_get_object (parent->builder,
			                                                              "eap_simple_password_entry"));
			g_assert (passwd_entry);

			nma_utils_update_password_storage (passwd_entry, flags,
			                                   NM_SETTING (s_8021x), method->password_flags_name);
		}
	}

	if (method->pkey_passphrase_requested) {
		g_object_set (s_8021x, NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD,
		              gtk_editable_get_text (GTK_EDITABLE (method->pkey_passphrase_entry)),
		              NULL);
	}
}

static void
update_secrets (NMAEap *parent, NMConnection *connection)
{
	nma_ws_helper_fill_secret_entry (connection,
	                                 GTK_EDITABLE (gtk_builder_get_object (parent->builder, "eap_simple_password_entry")),
	                                 NM_TYPE_SETTING_802_1X,
	                                 (HelperSecretFunc) nm_setting_802_1x_get_password);
	nma_ws_helper_fill_secret_entry (connection,
	                                 GTK_EDITABLE (gtk_builder_get_object (parent->builder, "eap_simple_pkey_passphrase_entry")),
	                                 NM_TYPE_SETTING_802_1X,
	                                 (HelperSecretFunc) nm_setting_802_1x_get_private_key_password);
}

static gboolean
stuff_changed (NMAEapSimple *method)
{
	nma_ws_changed_cb (NULL, method->ws_8021x);
	method->idle_func_id = 0;
	return FALSE;
}

static void
password_storage_changed (GObject *entry,
                          GParamSpec *pspec,
                          NMAEapSimple *method)
{
	gboolean always_ask;
	gboolean secrets_only = method->flags & NMA_EAP_SIMPLE_FLAG_SECRETS_ONLY;

	always_ask = always_ask_selected (method->password_entry);

	if (always_ask && !secrets_only) {
		/* we always clear this button and do not restore it
		 * (because we want to hide the password). */
		gtk_check_button_set_active (method->show_password, FALSE);
	}

	gtk_widget_set_sensitive (GTK_WIDGET (method->show_password),
	                          !always_ask || secrets_only);

	if (!method->idle_func_id)
		method->idle_func_id = g_idle_add ((GSourceFunc) stuff_changed, method);
}

/* Set the UI fields for user, password, always_ask and show_password to the
 * values as provided by method->ws_8021x. */
static void
set_userpass_ui (NMAEapSimple *method)
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

	password_storage_changed (NULL, NULL, method);
}

static void
widgets_realized (GtkWidget *widget, NMAEapSimple *method)
{
	set_userpass_ui (method);
}

static void
widgets_unrealized (GtkWidget *widget, NMAEapSimple *method)
{
	nma_ws_802_1x_set_userpass (method->ws_8021x,
	                     gtk_editable_get_text (GTK_EDITABLE (method->username_entry)),
	                     gtk_editable_get_text (GTK_EDITABLE (method->password_entry)),
	                     always_ask_selected (method->password_entry),
	                     gtk_check_button_get_active (method->show_password));
}

static void
destroy (NMAEap *parent)
{
	NMAEapSimple *method = (NMAEapSimple *) parent;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_simple_grid"));
	g_assert (widget);
	g_signal_handlers_disconnect_by_data (widget, method);

	g_signal_handlers_disconnect_by_data (method->password_entry, method);

	nm_clear_g_source (&method->idle_func_id);
}

NMAEapSimple *
nma_eap_simple_new (NMAWs8021x *ws_8021x,
                    NMConnection *connection,
                    NMAEapSimpleType type,
                    NMAEapSimpleFlags flags,
                    const char *const*hints)
{
	NMAEap *parent;
	NMAEapSimple *method;
	GtkWidget *widget;
	NMSetting8021x *s_8021x = NULL;

	parent = nma_eap_init (NMA_WS (ws_8021x),
	                       sizeof (NMAEapSimple),
	                       validate,
	                       add_to_size_group,
	                       fill_connection,
	                       update_secrets,
	                       destroy,
	                       "/org/gnome/libnma/nma-eap-simple.ui",
	                       "eap_simple_grid",
	                       "eap_simple_username_entry",
	                       flags & NMA_EAP_SIMPLE_FLAG_PHASE2);
	if (!parent)
		return NULL;

	method = (NMAEapSimple *) parent;
	method->password_flags_name = NM_SETTING_802_1X_PASSWORD;
	method->ws_8021x = ws_8021x;
	method->flags = flags;
	method->type = type;
	g_assert (type < NMA_EAP_SIMPLE_TYPE_LAST);
	g_assert (   type != NMA_EAP_SIMPLE_TYPE_UNKNOWN
	          || hints);

	if (hints) {
		for (; *hints; hints++) {
			if (!strcmp (*hints, NM_SETTING_802_1X_IDENTITY))
				method->username_requested = TRUE;
			else if (!strcmp (*hints, NM_SETTING_802_1X_PASSWORD)) {
				method->password_requested = TRUE;
				method->password_flags_name = NM_SETTING_802_1X_PASSWORD;
			} else if (!strcmp (*hints, NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD))
				method->pkey_passphrase_requested = TRUE;
		}
	} else {
		method->username_requested = TRUE;
		method->password_requested = TRUE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_simple_grid"));
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "realize",
	                  (GCallback) widgets_realized,
	                  method);
	g_signal_connect (G_OBJECT (widget), "unrealize",
	                  (GCallback) widgets_unrealized,
	                  method);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_simple_username_entry"));
	g_assert (widget);
	method->username_entry = GTK_ENTRY (widget);

	if (   (method->flags & NMA_EAP_SIMPLE_FLAG_SECRETS_ONLY)
	    && !method->username_requested)
		gtk_widget_set_sensitive (widget, FALSE);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_simple_password_entry"));
	g_assert (widget);
	method->password_entry = GTK_ENTRY (widget);

	/* Create password-storage popup menu for password entry under entry's secondary icon */
	if (connection)
		s_8021x = nm_connection_get_setting_802_1x (connection);
	nma_utils_setup_password_storage (widget, 0, (NMSetting *) s_8021x, method->password_flags_name,
	                                  FALSE, flags & NMA_EAP_SIMPLE_FLAG_SECRETS_ONLY);

	g_signal_connect (method->password_entry, "notify::secondary-icon-name",
	                  G_CALLBACK (password_storage_changed),
	                  method);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "show_checkbutton_eapsimple"));
	g_assert (widget);
	method->show_password = GTK_CHECK_BUTTON (widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_simple_pkey_passphrase_entry"));
	g_assert (widget);
	method->pkey_passphrase_entry = GTK_ENTRY (widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_simple_username_entry"));
	if (!method->username_requested)
		gtk_widget_hide (widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_simple_password_entry"));
	if (!method->password_requested)
		gtk_widget_hide (widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_simple_pkey_passphrase_entry"));
	if (!method->pkey_passphrase_requested)
		gtk_widget_hide (widget);

	/* Initialize the UI fields with the security settings from method->ws_8021x.
	 * This will be done again when the widget gets realized. It must be done here as well,
	 * because the outer dialog will ask to 'validate' the connection before the security tab
	 * is shown/realized (to enable the 'Apply' button).
	 * As 'validate' accesses the contents of the UI fields, they must be initialized now, even
	 * if the widgets are not yet visible. */
	set_userpass_ui (method);

	return method;
}
