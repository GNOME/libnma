// SPDX-License-Identifier: LGPL-2.1+
/* NetworkManager Applet -- allow user control over networking
 *
 * Lubomir Rintel <lkundrak@v3.sk>
 *
 * Copyright (C) 2017,2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include "nma-ui-utils.h"
#include "nma-cert-chooser.h"
#include "nma-cert-chooser-button.h"
#include "utils.h"

#if GTK_CHECK_VERSION(4,0,0)
#define gtk3_widget_set_no_show_all(widget, show)
#else
#define gtk3_widget_set_no_show_all(widget, show) gtk_widget_set_no_show_all (widget, show);
#endif

#ifdef GCK
#include <gck/gck.h>
#else
typedef void GckAttribute;
typedef void GckAttributes;
typedef int GckUriFlags;
typedef struct {
	GckAttributes *attributes;
} GckUriData;

#define GCK_URI_FOR_OBJECT 0
#define CKA_CLASS 0

static GckUriData *
gck_uri_parse (const gchar *string, GckUriFlags flags, GError **error)
{
	return NULL;
}

static const GckAttribute *
gck_attributes_find (GckAttributes *attrs, gulong attr_type)
{
	return NULL;
}

static void
gck_uri_data_free (GckUriData *uri_data)
{
}
#endif

typedef struct {
        GtkWidget *key_button_label;
        GtkWidget *key_password_label;
        GtkWidget *cert_button_label;
        GtkWidget *cert_password_label;
        GtkWidget *key_button;
        GtkWidget *key_password;
        GtkWidget *cert_button;
        GtkWidget *cert_password;
        GtkWidget *show_password;

	NMACertChooserFlags flags;
	char *title;
} NMACertChooserPrivate;

struct _NMACertChooser {
        GtkGrid parent;
        NMACertChooserPrivate _priv;
};

struct _NMACertChooserClass {
        GtkGridClass parent_class;
};

/**
 * SECTION:nma-cert-chooser
 * @title: NMACertChooser
 *
 * Certificate chooser allows for selection of a certificate or
 * various schemes optionally accompanied with a key and passwords
 * or PIN.
 *
 * The widgets that implement this interface may allow selecting
 * the certificates from various sources such as files or cryptographic
 * tokens.
 */

enum {
	PROP_0,
	PROP_TITLE,
	PROP_FLAGS,
	LAST_PROP,
};

static GParamSpec *properties[LAST_PROP];

enum {
	CERT_VALIDATE,
	CERT_PASSWORD_VALIDATE,
	KEY_VALIDATE,
	KEY_PASSWORD_VALIDATE,
	CHANGED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE_WITH_CODE (NMACertChooser, nma_cert_chooser, GTK_TYPE_GRID,
                         G_ADD_PRIVATE (NMACertChooser))

static gboolean
accu_validation_error (GSignalInvocationHint *ihint,
                       GValue *return_accu,
                       const GValue *handler_return,
                       gpointer data)
{
	if (g_value_get_boxed (handler_return)) {
		g_value_copy (handler_return, return_accu);
		return FALSE;
	}

	return TRUE;
}

static gchar *
value_with_scheme_to_uri (const gchar *value, NMSetting8021xCKScheme scheme)
{
	switch (scheme) {
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		return g_strdup_printf (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH "%s", value);
	case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
		return g_strdup (value);
	default:
		g_return_val_if_reached (NULL);
	}
}

static gchar *
uri_to_value_with_scheme (const gchar *uri, NMSetting8021xCKScheme *scheme)
{
	if (!uri) {
		NM_SET_OUT (scheme, NM_SETTING_802_1X_CK_SCHEME_UNKNOWN);
		return NULL;
	}

	if (g_str_has_prefix (uri, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH)) {
		NM_SET_OUT (scheme, NM_SETTING_802_1X_CK_SCHEME_PATH);
		return g_uri_unescape_string (uri + NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH), NULL);
	}

	if (g_str_has_prefix (uri, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PKCS11)) {
		NM_SET_OUT (scheme, NM_SETTING_802_1X_CK_SCHEME_PKCS11);
		return g_strdup (uri);
	}

	g_return_val_if_reached (NULL);
}

/**
 * nma_cert_chooser_set_cert_uri:
 * @cert_chooser: certificate chooser button instance
 * @uri: the path or URI of a certificate
 *
 * Sets the certificate URI for the chooser button.
 *
 * Since: 1.8.0
 */
void
nma_cert_chooser_set_cert_uri (NMACertChooser *cert_chooser,
                               const gchar *uri)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	g_return_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser));

	if (uri == NULL || g_str_has_prefix (uri, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH)) {
		gtk_widget_set_sensitive (priv->cert_password, FALSE);
	} else if (g_str_has_prefix (uri, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PKCS11)) {
		gtk_widget_set_sensitive (priv->cert_password, TRUE);
		gtk_widget_show (priv->cert_password);
		gtk_widget_show (priv->show_password);
	} else {
		g_warning ("The certificate '%s' uses an unknown scheme\n", uri);
		return;
	}

	nma_cert_chooser_button_set_uri (NMA_CERT_CHOOSER_BUTTON (priv->cert_button), uri);
}

/**
 * nma_cert_chooser_set_cert:
 * @cert_chooser: certificate chooser button instance
 * @value: the path or URI of a certificate
 * @scheme: the scheme of the certificate path
 *
 * Sets the certificate location for the chooser button.
 *
 * Since: 1.8.0
 */
void
nma_cert_chooser_set_cert (NMACertChooser *cert_chooser,
                           const gchar *value,
                           NMSetting8021xCKScheme scheme)
{
	gs_free gchar *uri = NULL;

	g_return_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser));

	if (value)
		uri = value_with_scheme_to_uri (value, scheme);
	nma_cert_chooser_set_cert_uri (cert_chooser, uri);
}

/**
 * nma_cert_chooser_get_cert_uri:
 * @cert_chooser: certificate chooser button instance
 *
 * Gets the real certificate URI from the chooser button along with the scheme.
 *
 * Returns: (transfer full) (nullable): the certificate URI
 *
 * Since: 1.8.0
 */
gchar *
nma_cert_chooser_get_cert_uri (NMACertChooser *cert_chooser)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	g_return_val_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser), NULL);

	return g_strdup (nma_cert_chooser_button_get_uri (NMA_CERT_CHOOSER_BUTTON (priv->cert_button)));
}

/**
 * nma_cert_chooser_get_cert:
 * @cert_chooser: certificate chooser button instance
 * @scheme: (out): the scheme of the returned certificate path
 *
 * Gets the real certificate location from the chooser button along with the scheme.
 *
 * Returns: (transfer full) (nullable): the certificate path
 *
 * Since: 1.8.0
 */
gchar *
nma_cert_chooser_get_cert (NMACertChooser *cert_chooser, NMSetting8021xCKScheme *scheme)
{
	gs_free gchar *uri = NULL;

	g_return_val_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser), NULL);

	uri = nma_cert_chooser_get_cert_uri (cert_chooser);
	return uri_to_value_with_scheme (uri, scheme);
}

/**
 * nma_cert_chooser_set_cert_password:
 * @cert_chooser: certificate chooser button instance
 * @password: the certificate PIN or password
 *
 * Sets the password or a PIN that might be required to access the certificate.
 *
 * Since: 1.8.0
 */
void
nma_cert_chooser_set_cert_password (NMACertChooser *cert_chooser, const gchar *password)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	g_return_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser));
	g_return_if_fail (password);

	g_return_if_fail (priv->cert_password != NULL);
	if (password)
		gtk_editable_set_text (GTK_EDITABLE (priv->cert_password), password);
}

/**
 * nma_cert_chooser_get_cert_password:
 * @cert_chooser: certificate chooser button instance
 *
 * Obtains the password or a PIN that was be required to access the certificate.
 *
 * Returns: the certificate PIN or password
 *
 * Since: 1.8.0
 */
const gchar *
nma_cert_chooser_get_cert_password (NMACertChooser *cert_chooser)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);
	const gchar *text;

	g_return_val_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser), NULL);

	g_return_val_if_fail (priv->cert_password != NULL, NULL);
	text = gtk_editable_get_text (GTK_EDITABLE (priv->cert_password));

	return text && text[0] ? text : NULL;
}

/**
 * nma_cert_chooser_set_key_uri:
 * @cert_chooser: certificate chooser button instance
 * @uri: the URI of a key
 *
 * Sets the key URI for the chooser button.
 *
 * Since: 1.8.0
 */
void
nma_cert_chooser_set_key_uri (NMACertChooser *cert_chooser,
                              const gchar *uri)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	g_return_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser));

	if (uri) {
		gtk_widget_set_sensitive (priv->key_button, TRUE);
		gtk_widget_set_sensitive (priv->key_password, TRUE);
		gtk_widget_show (priv->key_password);
		gtk_widget_show (priv->show_password);
	} else {
		gtk_widget_set_sensitive (priv->key_password, FALSE);
		nma_cert_chooser_set_cert_password (cert_chooser, "");
	}

	nma_cert_chooser_button_set_uri (NMA_CERT_CHOOSER_BUTTON (priv->key_button), uri);
}

/**
 * nma_cert_chooser_set_key:
 * @cert_chooser: certificate chooser button instance
 * @value: the path or URI of a key
 * @scheme: the scheme of the key path
 *
 * Sets the key location for the chooser button.
 *
 * Since: 1.8.0
 */
void
nma_cert_chooser_set_key (NMACertChooser *cert_chooser,
                          const gchar *value,
                          NMSetting8021xCKScheme scheme)
{
	gs_free gchar *uri = NULL;

	g_return_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser));

	if (value)
		uri = value_with_scheme_to_uri (value, scheme);
	nma_cert_chooser_set_key_uri (cert_chooser, uri);
}

/**
 * nma_cert_chooser_get_key:
 * @cert_chooser: certificate chooser button instance
 * @scheme: (out): the scheme of the returned key path
 *
 * Gets the real key location from the chooser button along with the scheme.
 *
 * Returns: (transfer full) (nullable): the key path
 *
 * Since: 1.8.0
 */
gchar *
nma_cert_chooser_get_key (NMACertChooser *cert_chooser, NMSetting8021xCKScheme *scheme)
{
	gs_free gchar *uri = NULL;

	g_return_val_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser), NULL);

	uri = nma_cert_chooser_get_key_uri (cert_chooser);
	return uri_to_value_with_scheme (uri, scheme);
}

/**
 * nma_cert_chooser_get_key_uri:
 * @cert_chooser: certificate chooser button instance
 *
 * Gets the real key URI from the chooser button along with the scheme.
 *
 * Returns: (transfer full) (nullable): the key URI
 *
 * Since: 1.8.0
 */
gchar *
nma_cert_chooser_get_key_uri (NMACertChooser *cert_chooser)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	g_return_val_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser), NULL);

	return g_strdup (nma_cert_chooser_button_get_uri (NMA_CERT_CHOOSER_BUTTON (priv->key_button)));
}

/**
 * nma_cert_chooser_set_key_password:
 * @cert_chooser: certificate chooser button instance
 * @password: the key PIN or password
 *
 * Sets the password or a PIN that might be required to access the key.
 *
 * Since: 1.8.0
 */
void
nma_cert_chooser_set_key_password (NMACertChooser *cert_chooser, const gchar *password)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	g_return_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser));
	g_return_if_fail (password);

	g_return_if_fail (priv->key_password != NULL);
	if (password)
		gtk_editable_set_text (GTK_EDITABLE (priv->key_password), password);
}

/**
 * nma_cert_chooser_get_key_password:
 * @cert_chooser: certificate chooser button instance
 *
 * Obtains the password or a PIN that was be required to access the key.
 *
 * Returns: the key PIN or password
 *
 * Since: 1.8.0
 */
const gchar *
nma_cert_chooser_get_key_password (NMACertChooser *cert_chooser)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);
	const gchar *text;

	g_return_val_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser), NULL);

	g_return_val_if_fail (priv->key_password != NULL, NULL);
	text = gtk_editable_get_text (GTK_EDITABLE (priv->key_password));

	return text && text[0] ? text : NULL;
}

/**
 * nma_cert_chooser_add_to_size_group:
 * @cert_chooser: certificate chooser button instance
 * @group: a size group
 *
 * Adds the labels to the specified size group so that they are aligned
 * nicely with other entries in a form.
 *
 * It is expected that the NMACertChooser is a GtkGrid with two columns
 * with the labels in the first one.
 *
 * Since: 1.8.0
 */
void
nma_cert_chooser_add_to_size_group (NMACertChooser *cert_chooser, GtkSizeGroup *group)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	g_return_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser));

	gtk_size_group_add_widget (group, priv->cert_button_label);
	gtk_size_group_add_widget (group, priv->cert_password_label);
	gtk_size_group_add_widget (group, priv->key_button_label);
	gtk_size_group_add_widget (group, priv->key_password_label);
}

/**
 * nma_cert_chooser_validate:
 * @cert_chooser: certificate chooser button instance
 * @error: error return location
 *
 * Validates whether the chosen values make sense. The users can do further
 * validation by subscribing to the "*-changed" signals and returning an
 * error themselves.
 *
 * Returns: %TRUE if validation passes, %FALSE otherwise
 *
 * Since: 1.8.0
 */
gboolean
nma_cert_chooser_validate (NMACertChooser *cert_chooser, GError **error)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);
	GError *local = NULL;

	g_return_val_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser), TRUE);

	if (!nma_cert_chooser_button_get_uri (NMA_CERT_CHOOSER_BUTTON (priv->cert_button))) {
		g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("No certificate set"));
		return FALSE;
	}

	g_signal_emit_by_name (cert_chooser, "cert-validate", &local);
	if (local) {
		widget_set_error (priv->cert_button);
		g_propagate_error (error, local);
		return FALSE;
	} else {
		widget_unset_error (priv->cert_button);
	}

	g_signal_emit_by_name (cert_chooser, "cert-password-validate", &local);
	if (local) {
		widget_set_error (priv->cert_password);
		g_propagate_error (error, local);
		return FALSE;
	} else {
		widget_unset_error (priv->cert_password);
	}

	if (gtk_widget_get_visible (priv->key_button)) {
		if (!nma_cert_chooser_button_get_uri (NMA_CERT_CHOOSER_BUTTON (priv->cert_button))) {
			g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC, _("No key set"));
			return FALSE;
		}

		g_signal_emit_by_name (cert_chooser, "key-validate", &local);
		if (local) {
			widget_set_error (priv->key_button);
			g_propagate_error (error, local);
			return FALSE;
		} else {
			widget_unset_error (priv->key_button);
		}

		g_signal_emit_by_name (cert_chooser, "key-password-validate", &local);
		if (local) {
			widget_set_error (priv->key_password);
			g_propagate_error (error, local);
			return FALSE;
		} else {
			widget_unset_error (priv->key_password);
		}
	}

	return TRUE;
}

/**
 * nma_cert_chooser_setup_cert_password_storage:
 * @cert_chooser: certificate chooser button instance
 * @initial_flags: initial secret flags to setup password menu from
 * @setting: #NMSetting containing the password, or NULL
 * @password_flags_name: name of the secret flags (like psk-flags), or NULL
 * @with_not_required: whether to include "Not required" menu item
 * @ask_mode: %TRUE if the entry is shown in ASK mode
 *
 * This method basically calls nma_utils_setup_password_storage()
 * on the certificate password entry, in case one is present.
 *
 * Since: 1.8.0
 */
void
nma_cert_chooser_setup_cert_password_storage (NMACertChooser *cert_chooser,
                                              NMSettingSecretFlags initial_flags,
                                              NMSetting *setting,
                                              const char *password_flags_name,
                                              gboolean with_not_required,
                                              gboolean ask_mode)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	g_return_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser));

	nma_utils_setup_password_storage (priv->cert_password,
	                                  initial_flags,
	                                  setting,
	                                  password_flags_name,
	                                  with_not_required,
	                                  ask_mode);
}

/**
 * nma_cert_chooser_update_cert_password_storage:
 * @cert_chooser: certificate chooser button instance
 * @secret_flags: secret flags to set
 * @setting: #NMSetting containing the password, or NULL
 * @password_flags_name: name of the secret flags (like psk-flags), or NULL
 *
 * This method basically calls nma_utils_update_password_storage()
 * on the certificate password entry, in case one is present.
 *
 * Since: 1.8.0
 */
void
nma_cert_chooser_update_cert_password_storage (NMACertChooser *cert_chooser,
                                               NMSettingSecretFlags secret_flags,
                                               NMSetting *setting,
                                               const char *password_flags_name)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	g_return_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser));

	nma_utils_update_password_storage (priv->cert_password,
	                                   secret_flags,
	                                   setting,
	                                   password_flags_name);
}

/**
 * nma_cert_chooser_get_cert_password_flags:
 * @cert_chooser: certificate chooser button instance
 *
 * Returns secret flags corresponding to the certificate password
 * if one is present. The chooser would typically call into
 * nma_utils_menu_to_secret_flags() for the certificate password
 * entry.
 *
 * Returns: secret flags corresponding to the certificate password
 *
 * Since: 1.8.0
 */
NMSettingSecretFlags
nma_cert_chooser_get_cert_password_flags (NMACertChooser *cert_chooser)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	g_return_val_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser),
	                      NM_SETTING_SECRET_FLAG_NONE);

	return nma_utils_menu_to_secret_flags (priv->cert_password);
}

/**
 * nma_cert_chooser_setup_key_password_storage:
 * @cert_chooser: certificate chooser button instance
 * @initial_flags: initial secret flags to setup password menu from
 * @setting: #NMSetting containing the password, or NULL
 * @password_flags_name: name of the secret flags (like psk-flags), or NULL
 * @with_not_required: whether to include "Not required" menu item
 * @ask_mode: %TRUE if the entry is shown in ASK mode
 *
 * This method basically calls nma_utils_setup_password_storage()
 * on the key password entry, in case one is present.
 *
 * Since: 1.8.0
 */
void
nma_cert_chooser_setup_key_password_storage (NMACertChooser *cert_chooser,
                                             NMSettingSecretFlags initial_flags,
                                             NMSetting *setting,
                                             const char *password_flags_name,
                                             gboolean with_not_required,
                                             gboolean ask_mode)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	g_return_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser));

	nma_utils_setup_password_storage (priv->key_password,
	                                  initial_flags,
	                                  setting,
	                                  password_flags_name,
	                                  with_not_required,
	                                  ask_mode);
}

/**
 * nma_cert_chooser_update_key_password_storage:
 * @cert_chooser: certificate chooser button instance
 * @secret_flags: secret flags to set
 * @setting: #NMSetting containing the password, or NULL
 * @password_flags_name: name of the secret flags (like psk-flags), or NULL
 *
 * This method basically calls nma_utils_update_password_storage()
 * on the key password entry, in case one is present.
 *
 * Since: 1.8.0
 */
void
nma_cert_chooser_update_key_password_storage (NMACertChooser *cert_chooser,
                                               NMSettingSecretFlags secret_flags,
                                               NMSetting *setting,
                                               const char *password_flags_name)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	g_return_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser));

	nma_utils_update_password_storage (priv->key_password,
	                                   secret_flags,
	                                   setting,
	                                   password_flags_name);
}

/**
 * nma_cert_chooser_get_key_password_flags:
 * @cert_chooser: certificate chooser button instance
 *
 * Returns secret flags corresponding to the key password
 * if one is present. The chooser would typically call into
 * nma_utils_menu_to_secret_flags() for the key password
 * entry.
 *
 * Returns: secret flags corresponding to the key password
 *
 * Since: 1.8.0
 */
NMSettingSecretFlags
nma_cert_chooser_get_key_password_flags (NMACertChooser *cert_chooser)
{
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	g_return_val_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser),
	                      NM_SETTING_SECRET_FLAG_NONE);

	return nma_utils_menu_to_secret_flags (priv->key_password);
}

static void
cert_changed_cb (NMACertChooserButton *button, gpointer user_data)
{
	NMACertChooser *cert_chooser = NMA_CERT_CHOOSER (user_data);
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);
	GckUriData *uri_data;
	gchar *pin = NULL;
	const gchar *uri;

	uri = nma_cert_chooser_button_get_uri (button);
	if (!uri)
		return;
	uri_data = gck_uri_parse (uri, GCK_URI_FOR_OBJECT, NULL);

	if (nma_cert_chooser_button_get_remember_pin (button))
		pin = nma_cert_chooser_button_get_pin (button);
	if (pin)
		gtk_editable_set_text (GTK_EDITABLE (priv->cert_password), pin);

	gtk_widget_set_sensitive (priv->cert_password, uri_data != NULL);

	if (!gtk_widget_get_sensitive (priv->key_button)) {
		gtk_widget_set_sensitive (priv->key_button, TRUE);

		if (uri_data) {
			/* URI that is good both for a certificate and for a key. */
			if (!gck_attributes_find (uri_data->attributes, CKA_CLASS)) {
				nma_cert_chooser_button_set_uri (NMA_CERT_CHOOSER_BUTTON (priv->key_button), uri);
				gtk_widget_set_sensitive (priv->key_password, TRUE);
				if (pin)
					gtk_editable_set_text (GTK_EDITABLE (priv->key_password), pin);
			}
		}
	}

	if (uri_data)
		gck_uri_data_free (uri_data);
	if (pin)
		g_free (pin);

	g_signal_emit_by_name (user_data, "changed");
}

static void
cert_password_changed_cb (GtkEntry *entry, gpointer user_data)
{
	g_signal_emit_by_name (user_data, "changed");
}

static void
key_password_changed_cb (GtkEntry *entry, gpointer user_data)
{
	g_signal_emit_by_name (user_data, "changed");
}

static void
key_changed_cb (NMACertChooserButton *button, gpointer user_data)
{
	NMACertChooser *cert_chooser = NMA_CERT_CHOOSER (user_data);
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);
	gchar *pin = NULL;

	if (nma_cert_chooser_button_get_remember_pin (button))
		pin = nma_cert_chooser_button_get_pin (button);
	if (pin) {
		gtk_editable_set_text (GTK_EDITABLE (priv->key_password), pin);
		g_free (pin);
	}

	gtk_widget_set_sensitive (priv->key_password, TRUE);
	g_signal_emit_by_name (user_data, "changed");
}

static void
constructed (GObject *object)
{
	NMACertChooser *cert_chooser = NMA_CERT_CHOOSER (object);
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);
	NMACertChooserButtonFlags button_flags = NMA_CERT_CHOOSER_BUTTON_FLAG_NONE;
	gs_free gchar *mnemonic_escaped = NULL;
	gchar *text;
	char **split;

	G_OBJECT_CLASS (nma_cert_chooser_parent_class)->constructed (object);

	split = g_strsplit (priv->title, "_", -1);
	mnemonic_escaped = g_strjoinv("__", split);
	g_strfreev (split);

	if (priv->flags & NMA_CERT_CHOOSER_FLAG_PEM)
		button_flags |= NMA_CERT_CHOOSER_BUTTON_FLAG_PEM;

	/* The certificate chooser */

	priv->cert_button = nma_cert_chooser_button_new (button_flags);
	gtk_label_set_mnemonic_widget (GTK_LABEL (priv->cert_button_label), priv->cert_button);
	g_object_bind_property (priv->cert_button, "visible",
	                        priv->cert_button_label, "visible",
	                        G_BINDING_SYNC_CREATE);
	g_object_bind_property (priv->cert_button, "sensitive",
	                        priv->cert_button_label, "sensitive",
	                        G_BINDING_SYNC_CREATE);

	gtk_grid_attach (GTK_GRID (cert_chooser), priv->cert_button, 1, 0, 1, 1);
	gtk_widget_set_hexpand (priv->cert_button, TRUE);
	gtk_widget_show (priv->cert_button);
	gtk3_widget_set_no_show_all (priv->cert_button, TRUE);

	g_signal_connect (priv->cert_button, "changed",
	                  G_CALLBACK (cert_changed_cb), cert_chooser);

	text = g_strdup_printf (_("Choose a %s Certificate"), priv->title);
	nma_cert_chooser_button_set_title (NMA_CERT_CHOOSER_BUTTON (priv->cert_button), text);
	g_free (text);

	text = g_strdup_printf (_("%s _certificate"), mnemonic_escaped);
	gtk_label_set_text_with_mnemonic (GTK_LABEL (priv->cert_button_label), text);
	g_free (text);

	text = g_strdup_printf (_("%s certificate _password"), mnemonic_escaped);
	gtk_label_set_text_with_mnemonic (GTK_LABEL (priv->cert_password_label), text);
	g_free (text);

	/* The key chooser */

	priv->key_button = nma_cert_chooser_button_new (button_flags |
							NMA_CERT_CHOOSER_BUTTON_FLAG_KEY);
	gtk_label_set_mnemonic_widget (GTK_LABEL (priv->key_button_label), priv->key_button);
	g_object_bind_property (priv->key_button, "visible",
	                        priv->key_button_label, "visible",
	                        G_BINDING_SYNC_CREATE);
	g_object_bind_property (priv->key_button, "sensitive",
	                        priv->key_button_label, "sensitive",
	                        G_BINDING_SYNC_CREATE);

	gtk_grid_attach (GTK_GRID (cert_chooser), priv->key_button, 1, 2, 1, 1);
	gtk_widget_set_hexpand (priv->key_button, TRUE);
	gtk_widget_set_sensitive (priv->key_button, FALSE);
	gtk_widget_show (priv->key_button);
	gtk3_widget_set_no_show_all (priv->key_button, TRUE);

        g_signal_connect (priv->key_button, "changed",
	                  G_CALLBACK (key_changed_cb), cert_chooser);

	text = g_strdup_printf (_("Choose a key for %s Certificate"), priv->title);
	nma_cert_chooser_button_set_title (NMA_CERT_CHOOSER_BUTTON (priv->key_button), text);
	g_free (text);

	text = g_strdup_printf (_("%s private _key"), mnemonic_escaped);
	gtk_label_set_text_with_mnemonic (GTK_LABEL (priv->key_button_label), text);
	g_free (text);

	text = g_strdup_printf (_("%s key _password"), mnemonic_escaped);
	gtk_label_set_text_with_mnemonic (GTK_LABEL (priv->key_password_label), text);
	g_free (text);

	/* Hide irrelevant things */

	if (priv->flags & NMA_CERT_CHOOSER_FLAG_CERT) {
		gtk_widget_hide (priv->key_button);
		gtk_widget_hide (priv->key_password);
	}

	if (priv->flags & NMA_CERT_CHOOSER_FLAG_PASSWORDS) {
		gtk_widget_hide (priv->cert_button);
		gtk_widget_hide (priv->key_button);

		/* With FLAG_PASSWORDS the user can't pick a different key or a
		 * certificate, so there's no point in showing inactive password
		 * inputs. */
		if (!gtk_widget_get_sensitive (priv->cert_password)) {
			gtk_widget_hide (priv->cert_password);
		}
		if (!gtk_widget_get_sensitive (priv->key_password)) {
			gtk_widget_hide (priv->key_password);
		}
	}

	if (priv->flags & NMA_CERT_CHOOSER_FLAG_PEM) {
		gtk_widget_hide (priv->cert_password);
	}

	if (priv->flags & NMA_CERT_CHOOSER_FLAG_NO_PASSWORDS) {
		gtk_widget_hide (priv->cert_password);
		gtk_widget_hide (priv->key_password);
	}

	gtk_widget_set_visible (priv->show_password,
	                        gtk_widget_get_visible (priv->cert_password) ||
	                        gtk_widget_get_visible (priv->key_password));
}

static void
set_property (GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
	NMACertChooser *cert_chooser = NMA_CERT_CHOOSER (object);
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	g_return_if_fail (NMA_IS_CERT_CHOOSER (cert_chooser));

	switch (property_id) {
	case PROP_TITLE:
		priv->title = g_strdup (g_value_get_string (value));
		break;
	case PROP_FLAGS:
		priv->flags = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMACertChooser *cert_chooser = NMA_CERT_CHOOSER (object);
	NMACertChooserPrivate *priv = nma_cert_chooser_get_instance_private (cert_chooser);

	nm_clear_g_free (&priv->title);

	G_OBJECT_CLASS (nma_cert_chooser_parent_class)->dispose (object);
}

static void
nma_cert_chooser_class_init (NMACertChooserClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GtkWidgetClass *widget_class = GTK_WIDGET_CLASS (klass);

	object_class->constructed = constructed;
	object_class->set_property = set_property;
	object_class->dispose = dispose;

	/**
	 * NMACertChooser::title:
	 *
	 * Name of the certificate or certificate/key pair to be chosen.
	 * Used in labels and chooser dialog titles.
	 *
	 * Since: 1.8.0
	 */
	properties[PROP_TITLE] = g_param_spec_string ("title",
	                                             "Title",
	                                             "Certificate Chooser Title",
	                                             NULL,
	                                               G_PARAM_WRITABLE
	                                             | G_PARAM_CONSTRUCT_ONLY
	                                             | G_PARAM_STATIC_STRINGS);

	/**
	 * NMACertChooser::flags:
	 *
	 * The #NMACertChooserFlags flags that influnce which chooser
	 * implementation is used and configure its behavior.
	 *
	 * Since: 1.8.0
	 */
	properties[PROP_FLAGS] = g_param_spec_uint ("flags",
	                                            "Flags",
	                                            "Certificate Chooser Flags",
	                                            NMA_CERT_CHOOSER_FLAG_NONE,
	                                              NMA_CERT_CHOOSER_FLAG_CERT
	                                            | NMA_CERT_CHOOSER_FLAG_PASSWORDS
	                                            | NMA_CERT_CHOOSER_FLAG_PEM
	                                            | NMA_CERT_CHOOSER_FLAG_NO_PASSWORDS,
	                                            NMA_CERT_CHOOSER_FLAG_NONE,
	                                              G_PARAM_WRITABLE
	                                            | G_PARAM_CONSTRUCT_ONLY
	                                            | G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, LAST_PROP, properties);

	/**
	 * NMACertChooser::cert-validate:
	 *
	 * Emitted when the certificate needs validation. The handlers can indicate that
	 * the certificate is invalid by returning an error, which blocks further
	 * signal processing and causes a call to nma_cert_chooser_validate()
	 * to fail.
	 *
	 * Since: 1.8.0
	 */
	signals[CERT_VALIDATE] = g_signal_new ("cert-validate",
	                                       NMA_TYPE_CERT_CHOOSER,
	                                       G_SIGNAL_RUN_LAST,
	                                       0,
	                                       accu_validation_error, NULL, NULL,
	                                       G_TYPE_ERROR, 0);

	/**
	 * NMACertChooser::cert-password-validate:
	 *
	 * Emitted when the certificate password needs validation. The handlers
	 * can indicate that the password is invalid by returning an error, which blocks further
	 * signal processing and causes a call to nma_cert_chooser_validate()
	 * to fail.
	 *
	 * Since: 1.8.0
	 */
	signals[CERT_PASSWORD_VALIDATE] = g_signal_new ("cert-password-validate",
	                                                NMA_TYPE_CERT_CHOOSER,
	                                                G_SIGNAL_RUN_LAST,
	                                                0,
	                                                accu_validation_error, NULL, NULL,
	                                                G_TYPE_ERROR, 0);

	/**
	 * NMACertChooser::key-validate:
	 *
	 * Emitted when the key needs validation. The handlers can indicate that
	 * the key is invalid by returning an error, which blocks further
	 * signal processing and causes a call to nma_cert_chooser_validate()
	 * to fail.
	 *
	 * Since: 1.8.0
	 */
	signals[KEY_VALIDATE] = g_signal_new ("key-validate",
	                                      NMA_TYPE_CERT_CHOOSER,
	                                      G_SIGNAL_RUN_LAST,
	                                      0,
	                                      accu_validation_error, NULL, NULL,
	                                      G_TYPE_ERROR, 0);

	/**
	 * NMACertChooser::key-password-validate:
	 *
	 * Emitted when the key password needs validation. The handlers can indicate
	 * that the password is invalid by returning an error, which blocks further
	 * signal processing and causes a call to nma_cert_chooser_validate()
	 * to fail.
	 *
	 * Since: 1.8.0
	 */
	signals[KEY_PASSWORD_VALIDATE] = g_signal_new ("key-password-validate",
	                                               NMA_TYPE_CERT_CHOOSER,
	                                               G_SIGNAL_RUN_LAST,
	                                               0,
	                                               accu_validation_error, NULL, NULL,
	                                               G_TYPE_ERROR, 0);

	/**
	 * NMACertChooser::changed:
	 *
	 * Emitted when anything changes in the certificate chooser, be it a certificate,
	 * a key or associated passwords.
	 *
	 * Since: 1.8.0
	 */
	signals[CHANGED] = g_signal_new ("changed",
	                                 NMA_TYPE_CERT_CHOOSER,
	                                 G_SIGNAL_RUN_LAST | G_SIGNAL_NO_RECURSE,
	                                 0,
	                                 NULL, NULL, NULL,
	                                 G_TYPE_NONE, 0);

	gtk_widget_class_set_template_from_resource (widget_class,
	                                             "/org/gnome/libnma/nma-cert-chooser.ui");

	gtk_widget_class_bind_template_child_private (widget_class, NMACertChooser, cert_button_label);
	gtk_widget_class_bind_template_child_private (widget_class, NMACertChooser, cert_password);
	gtk_widget_class_bind_template_child_private (widget_class, NMACertChooser, cert_password_label);
	gtk_widget_class_bind_template_child_private (widget_class, NMACertChooser, key_button_label);
	gtk_widget_class_bind_template_child_private (widget_class, NMACertChooser, key_password);
	gtk_widget_class_bind_template_child_private (widget_class, NMACertChooser, key_password_label);
	gtk_widget_class_bind_template_child_private (widget_class, NMACertChooser, show_password);

	gtk_widget_class_bind_template_callback (widget_class, cert_password_changed_cb);
	gtk_widget_class_bind_template_callback (widget_class, key_password_changed_cb);
}

static void
nma_cert_chooser_init (NMACertChooser *cert_chooser)
{
	gtk_widget_init_template (GTK_WIDGET (cert_chooser));
}

/**
 * nma_cert_chooser_new:
 * @title: title of the certificate chooser dialog
 * @flags: the flags that configure the capabilities of the button
 *
 * Constructs the button that is capable of selecting a certificate
 * and a key.
 *
 * Returns: (transfer full): the certificate chooser button instance
 *
 * Since: 1.8.0
 */
GtkWidget *
nma_cert_chooser_new (const gchar *title, NMACertChooserFlags flags)
{
	return g_object_new (NMA_TYPE_CERT_CHOOSER,
	                     "title", title,
	                     "flags", flags,
	                     NULL);
}
