// SPDX-License-Identifier: LGPL-2.1+
/* NetworkManager Applet -- allow user control over networking
 *
 * Lubomir Rintel <lkundrak@v3.sk>
 *
 * Copyright (C) 2016 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include "nma-cert-chooser-button.h"
#include "utils.h"

#if WITH_GCR
#include "nma-pkcs11-cert-chooser-dialog.h"
#include <gck/gck.h>
#if !GCK_CHECK_VERSION(3,90,0)
#define gck_uri_data_parse gck_uri_parse
#endif
#endif

/**
 * SECTION:nma-cert-chooser-button
 * @title: NMACertChooserButton
 * @short_description: The PKCS\#11 or file certificate chooser button
 *
 * #NMACertChooserButton is a button that provides a dropdown of
 * PKCS\#11 slots present in the system and allows choosing a certificate
 * from either of them or a file.
 */

enum {
	CHANGED,
	LAST_SIGNAL,
};

enum {
	COLUMN_LABEL,
	COLUMN_SLOT,
	N_COLUMNS
};

typedef struct {
	gchar *title;
	gchar *uri;
	gchar *pin;
	gboolean remember_pin;
	NMACertChooserButtonFlags flags;
	GCancellable *cancellable;

	GtkWidget *button;
	GtkWidget *button_label;
} NMACertChooserButtonPrivate;

G_DEFINE_TYPE_WITH_CODE (NMACertChooserButton, nma_cert_chooser_button, GTK_TYPE_BOX,
                         G_ADD_PRIVATE (NMACertChooserButton))

enum {
	PROP_0,
	PROP_FLAGS,
	LAST_PROP
};

static void
update_title (NMACertChooserButton *button);

#if WITH_GCR
static gboolean
is_this_a_slot_nobody_loves (GckSlot *slot)
{
	GckSlotInfo *slot_info;
	gboolean ret_value = FALSE;

	slot_info = gck_slot_get_info (slot);
	if (!slot_info)
		return TRUE;

	/* The p11-kit CA trusts do use their filesystem paths for description. */
	if (g_str_has_prefix (slot_info->slot_description, "/"))
		ret_value = TRUE;
	else if (NM_IN_STRSET (slot_info->slot_description,
	                       "SSH Keys",
	                       "Secret Store",
	                       "User Key Storage"))
		ret_value = TRUE;

	gck_slot_info_free (slot_info);

	return ret_value;
}

static void
modules_initialized (GObject *object, GAsyncResult *res, gpointer user_data)
{
	NMACertChooserButton *self = NMA_CERT_CHOOSER_BUTTON (user_data);
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (self);
	GList *slots;
	GList *list_iter;
	GError *error = NULL;
	GList *modules;
	GtkTreeIter iter;
	GtkListStore *model;
	GckTokenInfo *info;
	gchar *label;

	modules = gck_modules_initialize_registered_finish (res, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		return;
	} else if (error) {
		/* The Front Fell Off. */
		g_warning ("Error getting registered modules: %s", error->message);
		g_clear_error (&error);
	}

	model = GTK_LIST_STORE (gtk_combo_box_get_model (GTK_COMBO_BOX (priv->button)));

	/* A separator. */
	gtk_list_store_insert_with_values (model, &iter, 2,
	                                   COLUMN_LABEL, NULL,
	                                   COLUMN_SLOT, NULL, -1);

	slots = gck_modules_get_slots (modules, FALSE);
	for (list_iter = slots; list_iter; list_iter = list_iter->next) {
		GckSlot *slot = GCK_SLOT (list_iter->data);

		if (is_this_a_slot_nobody_loves (slot))
			continue;

		info = gck_slot_get_token_info (slot);
		if (!info) {
			/* This happens when the slot has no token inserted.
			 * Don't add this one to the list. The other widgets
			 * assume gck_slot_get_token_info() don't fail and a slot
			 * for which it does is essentially useless as it can't be
			 * used for crafting an URI. */
			continue;
		}

		if ((info->flags & CKF_TOKEN_INITIALIZED) == 0)
			continue;

		if (info->label && *info->label) {
			label = g_strdup_printf ("%s\342\200\246", info->label);
		} else if (info->model && *info->model) {
			g_warning ("The token doesn't have a valid label");
			label = g_strdup_printf ("%s\342\200\246", info->model);
		} else {
			g_warning ("The token has neither valid label nor model");
			label = g_strdup ("(Unknown)\342\200\246");
		}
		gtk_list_store_insert_with_values (model, &iter, 2,
		                                   COLUMN_LABEL, label,
		                                   COLUMN_SLOT, slot, -1);
		g_free (label);
		gck_token_info_free (info);
	}

	g_list_free_full (slots, g_object_unref);
	g_list_free_full (modules, g_object_unref);
}

static char *
title_from_pkcs11 (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (button);
	GError *error = NULL;
	char *label = NULL;
	GckUriData *data;

	data = gck_uri_data_parse (priv->uri, GCK_URI_FOR_ANY, &error);
	if (data) {
		if (!gck_attributes_find_string (data->attributes, CKA_LABEL, &label)) {
			if (data->token_info) {
				g_free (label);
				label = g_strdup_printf (  priv->flags & NMA_CERT_CHOOSER_BUTTON_FLAG_KEY
							 ? _("Key in %s")
							 : _("Certificate in %s"),
							 data->token_info->label);
			}
		}
		gck_uri_data_free (data);
	} else {
		g_warning ("Bad URI '%s': %s\n", priv->uri, error->message);
		g_error_free (error);
	}

	return label;
}

static void
select_from_token (NMACertChooserButton *button, GckSlot *slot)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (button);
	GtkRoot *toplevel;
	GtkWidget *dialog;

	toplevel = gtk_widget_get_root (GTK_WIDGET (button));
	if (toplevel && !GTK_IS_WINDOW (toplevel))
		toplevel = NULL;

	dialog = nma_pkcs11_cert_chooser_dialog_new (slot,
	                                               priv->flags & NMA_CERT_CHOOSER_BUTTON_FLAG_KEY
	                                             ? CKO_PRIVATE_KEY
	                                             : CKO_CERTIFICATE,
	                                             priv->title,
	                                             (GtkWindow *) toplevel,
	                                             GTK_FILE_CHOOSER_ACTION_OPEN | GTK_DIALOG_USE_HEADER_BAR,
	                                             _("Select"), GTK_RESPONSE_ACCEPT,
	                                             _("Cancel"), GTK_RESPONSE_CANCEL,
	                                             NULL);
	if (nma_gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {
		if (priv->uri)
			g_free (priv->uri);
		priv->uri = nma_pkcs11_cert_chooser_dialog_get_uri (NMA_PKCS11_CERT_CHOOSER_DIALOG (dialog));
		if (priv->pin)
			g_free (priv->pin);
		priv->pin = nma_pkcs11_cert_chooser_dialog_get_pin (NMA_PKCS11_CERT_CHOOSER_DIALOG (dialog));
		priv->remember_pin = nma_pkcs11_cert_chooser_dialog_get_remember_pin (NMA_PKCS11_CERT_CHOOSER_DIALOG (dialog));
		update_title (button);
		g_signal_emit_by_name (button, "changed");
	}
	gtk_window_destroy (GTK_WINDOW (dialog));
}

static void
initialize_gck_modules (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (button);

	gck_modules_initialize_registered_async (priv->cancellable, modules_initialized, button);
}

static int
use_simple_button (NMACertChooserButtonFlags flags)
{
	return flags & NMA_CERT_CHOOSER_BUTTON_FLAG_PEM;
}
#else
typedef void GckSlot;
#define GCK_TYPE_SLOT G_TYPE_POINTER

static char *
title_from_pkcs11 (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (button);

	g_warning ("PKCS#11 URI, but GCR/GCK support not built in.");
	return g_strdup (priv->uri);
}

static void
select_from_token (NMACertChooserButton *button, GckSlot *slot)
{
	g_assert_not_reached ();
}

static void
initialize_gck_modules (NMACertChooserButton *button)
{
}

static int
use_simple_button (NMACertChooserButtonFlags flags)
{
	return TRUE;
}
#endif

static void
update_title (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (button);
	GtkTreeIter iter;
	GtkTreeModel *model;
	gs_free char *label = NULL;

	if (!priv->uri) {
		label = g_strdup (_("(None)"));
	} else if (g_str_has_prefix (priv->uri, "pkcs11:")) {
		label = title_from_pkcs11 (button);
	} else {
		label = priv->uri;
		if (g_str_has_prefix (label, "file://"))
			label += 7;
		if (g_strrstr (label, "/"))
			label = g_strrstr (label, "/") + 1;
		label = g_strdup (label);
	}

	if (priv->button_label) {
		g_return_if_fail (GTK_IS_BUTTON (priv->button));
		gtk_label_set_text (GTK_LABEL (priv->button_label), label);
	} else if (priv->button) {
		g_return_if_fail (GTK_IS_COMBO_BOX (priv->button));
		model = gtk_combo_box_get_model (GTK_COMBO_BOX (priv->button));

		if (!gtk_tree_model_get_iter_first (model, &iter))
			g_return_if_reached ();

		gtk_list_store_set (GTK_LIST_STORE (model), &iter,
		                    COLUMN_LABEL, label ?: _("(Unknown)"),
		                    -1);
	}
}

static void
select_from_file (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (button);
	GtkRoot *toplevel;
	GtkWidget *dialog;
	GFile *file;

	toplevel = gtk_widget_get_root (GTK_WIDGET (button));
	if (toplevel && !GTK_IS_WINDOW (toplevel))
		toplevel = NULL;

	dialog = gtk_file_chooser_dialog_new (priv->title,
	                                      (GtkWindow *) toplevel,
	                                      GTK_FILE_CHOOSER_ACTION_OPEN,
	                                      _("Select"), GTK_RESPONSE_ACCEPT,
	                                      _("Cancel"), GTK_RESPONSE_CANCEL,
	                                      NULL);

	if (priv->flags & NMA_CERT_CHOOSER_BUTTON_FLAG_KEY)
		gtk_file_chooser_set_filter (GTK_FILE_CHOOSER (dialog), utils_key_filter ());
	else
		gtk_file_chooser_set_filter (GTK_FILE_CHOOSER (dialog), utils_cert_filter ());

	if (priv->uri) {
		file = g_file_new_for_uri (priv->uri);
		gtk_file_chooser_set_file (GTK_FILE_CHOOSER (dialog), file, NULL);
		g_object_unref (file);
	}
	gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_ACCEPT);
	if (nma_gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {
		if (priv->uri)
			g_free (priv->uri);

		file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (dialog));
		priv->uri = g_file_get_uri (file);
		g_object_unref (file);

		if (priv->pin) {
			g_free (priv->pin);
			priv->pin = NULL;
		}
		priv->remember_pin = FALSE;
		update_title (button);
		g_signal_emit_by_name (button, "changed");
	}
	gtk_window_destroy (GTK_WINDOW (dialog));
}

static void
changed (GtkComboBox *combo_box, gpointer user_data)
{
	NMACertChooserButton *self = NMA_CERT_CHOOSER_BUTTON (user_data);
	GtkTreeIter iter;
	GtkTreeModel *model;
	gchar *label;
	GckSlot *slot;

	if (gtk_combo_box_get_active (combo_box) == 0)
		return;

	gtk_combo_box_popdown (combo_box);
	g_signal_stop_emission_by_name (combo_box, "changed");
	gtk_combo_box_get_active_iter (combo_box, &iter);

	model = gtk_combo_box_get_model (combo_box);
	gtk_tree_model_get (model, &iter,
	                    COLUMN_LABEL, &label,
	                    COLUMN_SLOT, &slot, -1);
	if (slot)
		select_from_token (self, slot);
	else
		select_from_file (self);

	g_free (label);
	g_clear_object (&slot);
	gtk_combo_box_set_active (combo_box, 0);
}

static gboolean
row_separator (GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	gchar *label;
	GckSlot *slot;

	gtk_tree_model_get (model, iter, 0, &label, 1, &slot, -1);
	if (label == NULL && slot == NULL)
		return TRUE;
	g_free (label);
	g_clear_object (&slot);

	return FALSE;
}

static void
create_cert_combo (NMACertChooserButton *self)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (self);
	GtkListStore *model;
	GtkTreeIter iter;
	GtkCellRenderer *cell;

	model = gtk_list_store_new (2, G_TYPE_STRING, GCK_TYPE_SLOT);
	priv->button = gtk_combo_box_new_with_model (GTK_TREE_MODEL (model));
	gtk_widget_set_hexpand (priv->button, TRUE);
	gtk_widget_show (priv->button);
	g_object_unref (model);

	gtk_box_append (GTK_BOX (self), priv->button);

	gtk_combo_box_set_popup_fixed_width (GTK_COMBO_BOX (priv->button), TRUE);
	gtk_combo_box_set_row_separator_func (GTK_COMBO_BOX (priv->button),
	                                      row_separator,
	                                      NULL,
	                                      NULL);

	/* The first entry with current object name. */
	gtk_list_store_insert_with_values (model, &iter, 0,
	                                   COLUMN_LABEL, NULL,
	                                   COLUMN_SLOT, NULL, -1);

	/* The separator and the last entry. The tokens will be added in between. */
	gtk_list_store_insert_with_values (model, &iter, 1,
	                                   COLUMN_LABEL, NULL,
	                                   COLUMN_SLOT, NULL, -1);
	gtk_list_store_insert_with_values (model, &iter, 2,
	                                   COLUMN_LABEL, _("Select from file\342\200\246"),
	                                   COLUMN_SLOT, NULL, -1);

	cell = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (priv->button), cell, FALSE);
	gtk_cell_layout_add_attribute (GTK_CELL_LAYOUT (priv->button), cell, "text", 0);

	g_signal_connect (priv->button, "changed", (GCallback) changed, self);

	gtk_combo_box_set_active (GTK_COMBO_BOX (priv->button), 0);
	initialize_gck_modules (self);
}

static void
create_file_button (NMACertChooserButton *self)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (self);
	GtkWidget *widget;
	GtkWidget *box;

	gtk_orientable_set_orientation (GTK_ORIENTABLE (self), GTK_ORIENTATION_VERTICAL);
	priv->button = gtk_button_new ();
	gtk_widget_show (priv->button);
	gtk_box_append (GTK_BOX (self), priv->button);
	g_signal_connect_swapped (priv->button, "clicked", (GCallback) select_from_file, self);

	box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 1);
	gtk_widget_show (box);
	gtk_button_set_child (GTK_BUTTON (priv->button), box);

	priv->button_label = gtk_label_new (NULL);
	gtk_widget_show (priv->button_label);
	gtk_label_set_ellipsize (GTK_LABEL (priv->button_label), PANGO_ELLIPSIZE_END);
	g_object_set (priv->button_label, "xalign", (gfloat) 0, NULL);
	gtk_widget_set_hexpand (priv->button_label, TRUE);
	gtk_box_append (GTK_BOX (box), priv->button_label);

	widget = gtk_image_new_from_icon_name ("document-open-symbolic");
	gtk_widget_show (widget);
	gtk_box_append (GTK_BOX (box), widget);
}

static void
constructed (GObject *object)
{
	NMACertChooserButton *self = NMA_CERT_CHOOSER_BUTTON (object);
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (self);

        G_OBJECT_CLASS (nma_cert_chooser_button_parent_class)->constructed (object);

	if (use_simple_button (priv->flags))
		create_file_button (self);
	else
		create_cert_combo (self);

	update_title (self);
}

static void
set_property (GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (NMA_CERT_CHOOSER_BUTTON (object));

	switch (property_id) {
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
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (NMA_CERT_CHOOSER_BUTTON (object));

	g_cancellable_cancel (priv->cancellable);
	g_clear_object (&priv->cancellable);

	nm_clear_g_free (&priv->title);
	nm_clear_g_free (&priv->uri);
	nm_clear_g_free (&priv->pin);

        G_OBJECT_CLASS (nma_cert_chooser_button_parent_class)->dispose (object);
}

static gboolean
mnemonic_activate (GtkWidget *widget, gboolean group_cycling)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (NMA_CERT_CHOOSER_BUTTON (widget));

	return gtk_widget_mnemonic_activate (priv->button, group_cycling);
}

static void
nma_cert_chooser_button_class_init (NMACertChooserButtonClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GtkWidgetClass *widget_class = GTK_WIDGET_CLASS (klass);

	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->set_property = set_property;
	widget_class->mnemonic_activate = mnemonic_activate;

	g_signal_new ("changed",
	              G_OBJECT_CLASS_TYPE(object_class),
	              G_SIGNAL_RUN_LAST,
	              0, NULL, NULL,
	              NULL,
	              G_TYPE_NONE, 0);

        g_object_class_install_property (object_class, PROP_FLAGS,
		g_param_spec_uint ("flags", NULL, NULL,
		                   NMA_CERT_CHOOSER_BUTTON_FLAG_NONE,
		                     NMA_CERT_CHOOSER_BUTTON_FLAG_KEY
		                   | NMA_CERT_CHOOSER_BUTTON_FLAG_PEM,
		                   NMA_CERT_CHOOSER_BUTTON_FLAG_NONE,
		                     G_PARAM_WRITABLE
		                   | G_PARAM_CONSTRUCT_ONLY
		                   | G_PARAM_STATIC_STRINGS));
}

static void
nma_cert_chooser_button_init (NMACertChooserButton *self)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (self);

	priv->cancellable = g_cancellable_new ();
}

/**
 * nma_cert_chooser_button_set_title:
 * @button: the #NMACertChooserButton instance
 * @title: the title of the token or file chooser dialogs
 *
 * Set the title of file or PKCS\#11 object chooser dialogs.
 */
void
nma_cert_chooser_button_set_title (NMACertChooserButton *button, const gchar *title)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (button);

	if (priv->title)
		g_free (priv->title);
	priv->title = g_strdup (title);
}

/**
 * nma_cert_chooser_button_get_uri:
 * @button: the #NMACertChooserButton instance
 *
 * Obtain the URI of the selected obejct -- either of
 * "pkcs11" or "file" scheme.
 *
 * Returns: the URI or %NULL if none was selected.
 */
const gchar *
nma_cert_chooser_button_get_uri (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (button);

	return priv->uri;
}

/**
 * nma_cert_chooser_button_set_uri:
 * @button: the #NMACertChooserButton instance
 * @uri: the URI
 *
 * Set the chosen URI to given string.
 */
void
nma_cert_chooser_button_set_uri (NMACertChooserButton *button, const gchar *uri)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (button);

	if (priv->uri)
		g_free (priv->uri);
	priv->uri = g_strdup (uri);
	update_title (button);
}

/**
 * nma_cert_chooser_button_get_pin:
 * @button: the #NMACertChooserButton instance
 *
 * Obtain the PIN that was used to unlock the token.
 *
 * Returns: the PIN, %NULL if the token was not logged into or an emtpy
 *   string ("") if the protected authentication path was used.
 */
gchar *
nma_cert_chooser_button_get_pin (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (button);

	return g_strdup (priv->pin);
}

/**
 * nma_cert_chooser_button_get_remember_pin:
 * @button: the #NMACertChooserButton instance
 *
 * Obtain the value of the "Remember PIN" checkbox during the token login.
 *
 * Returns: TRUE if the user chose to remember the PIN, FALSE
 *   if not or if the tokin was not logged into at all.
 */
gboolean
nma_cert_chooser_button_get_remember_pin (NMACertChooserButton *button)
{
	NMACertChooserButtonPrivate *priv = nma_cert_chooser_button_get_instance_private (button);

	return priv->remember_pin;
}

/**
 * nma_cert_chooser_button_new:
 * @flags: the flags configuring the behavior of the chooser dialogs
 *
 * Creates the new button that can select certificates from
 * files or PKCS\#11 tokens.
 *
 * Returns: the newly created #NMACertChooserButton
 */
GtkWidget *
nma_cert_chooser_button_new (NMACertChooserButtonFlags flags)
{
	return g_object_new (NMA_TYPE_CERT_CHOOSER_BUTTON, "flags", flags, NULL);
}
