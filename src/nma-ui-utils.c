// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2015 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include "nma-ui-utils.h"

/*---------------------------------------------------------------------------*/
/* Password storage icon */

#define PASSWORD_STORAGE_TAG		"password-storage"

typedef enum {
	ITEM_STORAGE_USER    = 0,
	ITEM_STORAGE_SYSTEM  = 1,
	ITEM_STORAGE_ASK     = 2,
	ITEM_STORAGE_UNUSED  = 3,
	__ITEM_STORAGE_MAX,
	ITEM_STORAGE_MAX = __ITEM_STORAGE_MAX - 1,
} MenuItem;

static const char *icon_name_table[ITEM_STORAGE_MAX + 1] = {
	[ITEM_STORAGE_USER]    = "user-info-symbolic",
	[ITEM_STORAGE_SYSTEM]  = "system-users-symbolic",
	[ITEM_STORAGE_ASK]     = "dialog-question-symbolic",
	[ITEM_STORAGE_UNUSED]  = "edit-clear-all-symbolic",
};
static const char *icon_desc_table[ITEM_STORAGE_MAX + 1] = {
	[ITEM_STORAGE_USER]    = N_("Store the password only for this user"),
	[ITEM_STORAGE_SYSTEM]  = N_("Store the password for all users"),
	[ITEM_STORAGE_ASK]     = N_("Ask for this password every time"),
	[ITEM_STORAGE_UNUSED]  = N_("The password is not required"),
};

static void
g_free_str0 (gpointer mem)
{
	/* g_free a char pointer and set it to 0 before (for passwords). */
	if (mem) {
		char *p = mem;
		memset (p, 0, strlen (p));
		g_free (p);
	}
}

typedef struct {
	GtkWidget *popup_menu;
	GtkWidget *item[4];
	gboolean ask_mode;
	gboolean with_not_required;
} PasswordStorageData;

static void
change_password_storage_icon (GtkWidget *passwd_entry, MenuItem item)
{
	PasswordStorageData *data;
	const char *old_pwd;
	int changed;

	g_return_if_fail (item >= 0 && item <= ITEM_STORAGE_MAX);

	gtk_entry_set_icon_from_icon_name (GTK_ENTRY (passwd_entry),
	                                   GTK_ENTRY_ICON_SECONDARY,
	                                   icon_name_table[item]);
	gtk_entry_set_icon_tooltip_text (GTK_ENTRY (passwd_entry),
	                                 GTK_ENTRY_ICON_SECONDARY,
	                                 _(icon_desc_table[item]));

	data = g_object_get_data (G_OBJECT (passwd_entry), PASSWORD_STORAGE_TAG);

	/* We want to make entry insensitive when ITEM_STORAGE_ASK is selected
	 * Unfortunately, making GtkEntry insensitive will also make the icon
	 * insensitive, which prevents user from reverting the action.
	 * Let's workaround that by disabling focus for entry instead of
	 * sensitivity change.
	*/
	if (   (item == ITEM_STORAGE_ASK && !data->ask_mode)
	    || item == ITEM_STORAGE_UNUSED) {
		/* Store the old password */
		old_pwd = gtk_editable_get_text (GTK_EDITABLE (passwd_entry));
		if (old_pwd && *old_pwd)
			g_object_set_data_full (G_OBJECT (passwd_entry), "password-old",
		                                g_strdup (old_pwd), g_free_str0);

		changed = g_strcmp0 (gtk_editable_get_text (GTK_EDITABLE (passwd_entry)), "") != 0;
		if (changed)
			gtk_editable_set_text (GTK_EDITABLE (passwd_entry), "");

		if (gtk_widget_is_focus (passwd_entry))
			gtk_widget_child_focus (((GtkWidget *)gtk_widget_get_root (passwd_entry)), GTK_DIR_TAB_BACKWARD);
		gtk_widget_set_can_focus (passwd_entry, FALSE);
	} else {
		/* Set the old password to the entry */
		old_pwd = g_object_get_data (G_OBJECT (passwd_entry), "password-old");
		changed = g_strcmp0 (gtk_editable_get_text (GTK_EDITABLE (passwd_entry)), old_pwd) != 0;
		if (old_pwd && *old_pwd && changed)
			gtk_editable_set_text (GTK_EDITABLE (passwd_entry), old_pwd);
		g_object_set_data (G_OBJECT (passwd_entry), "password-old", NULL);

		if (!gtk_widget_get_can_focus (passwd_entry)) {
			gtk_widget_set_can_focus (passwd_entry, TRUE);
			gtk_widget_grab_focus (passwd_entry);
		}
	}
}

static MenuItem
secret_flags_to_menu_item (NMSettingSecretFlags flags, gboolean with_not_required)
{
	MenuItem idx;

	if (flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
		idx = ITEM_STORAGE_ASK;
	else if (with_not_required && (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
		idx = ITEM_STORAGE_UNUSED;
	else if (flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED)
		idx = ITEM_STORAGE_USER;
	else
		idx = ITEM_STORAGE_SYSTEM;

	return idx;
}

static NMSettingSecretFlags
menu_item_to_secret_flags (MenuItem item)
{
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	switch (item) {
	case ITEM_STORAGE_USER:
		flags |= NM_SETTING_SECRET_FLAG_AGENT_OWNED;
		break;
	case ITEM_STORAGE_ASK:
		flags |= NM_SETTING_SECRET_FLAG_NOT_SAVED;
		break;
	case ITEM_STORAGE_UNUSED:
		flags |= NM_SETTING_SECRET_FLAG_NOT_REQUIRED;
		break;
	case ITEM_STORAGE_SYSTEM:
	default:
		break;
	}
	return flags;
}

typedef struct {
	NMSetting *setting;
	char *password_flags_name;
	MenuItem item_number;
	GtkWidget *passwd_entry;
} PopupMenuItemInfo;

static void
popup_menu_item_info_destroy (gpointer data, GClosure *closure)
{
	PopupMenuItemInfo *info = (PopupMenuItemInfo *) data;

	if (info->setting)
		g_object_unref (info->setting);
	g_clear_pointer (&info->password_flags_name, g_free);
	if (info->passwd_entry)
		g_object_remove_weak_pointer (G_OBJECT (info->passwd_entry), (gpointer *) &info->passwd_entry);
	g_slice_free (PopupMenuItemInfo, info);
}

static void
activate_menu_item_cb (GtkCheckButton *menuitem, gpointer user_data)
{
	PopupMenuItemInfo *info = (PopupMenuItemInfo *) user_data;
	PasswordStorageData *data;
	NMSettingSecretFlags flags;

	/* Update password flags according to the password-storage popup menu */
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (menuitem))) {
		data = g_object_get_data (G_OBJECT (info->passwd_entry), PASSWORD_STORAGE_TAG);
		flags = menu_item_to_secret_flags (info->item_number);

		/* Update the secret flags in the setting */
		if (info->setting)
			nm_setting_set_secret_flags (info->setting, info->password_flags_name,
			                             flags, NULL);

		/* Change icon */
		if (info->passwd_entry) {
			change_password_storage_icon (info->passwd_entry, info->item_number);

			/* Emit "changed" signal on the entry */
			g_signal_emit_by_name (G_OBJECT (info->passwd_entry), "changed");
		}

#if GTK_CHECK_VERSION(3,22,0)
		NM_LIBNM_COMPAT_UNDEPRECATE(gtk_popover_popdown (GTK_POPOVER (data->popup_menu)));
#else
		gtk_widget_hide (GTK_WIDGET (data->popup_menu));
#endif
	}
}

static void
popup_menu_item_info_register (GtkWidget *item,
                               NMSetting *setting,
                               const char *password_flags_name,
                               MenuItem item_number,
                               GtkWidget *passwd_entry)
{
	PopupMenuItemInfo *info;

	info = g_slice_new0 (PopupMenuItemInfo);
	info->setting = setting ? g_object_ref (setting) : NULL;
	info->password_flags_name = g_strdup (password_flags_name);
	info->item_number = item_number;
	info->passwd_entry = passwd_entry;

	if (info->passwd_entry)
		g_object_add_weak_pointer (G_OBJECT (info->passwd_entry), (gpointer *) &info->passwd_entry);

	g_signal_connect_data (item, "toggled",
	                       G_CALLBACK (activate_menu_item_cb),
	                       info,
	                       (GClosureNotify) popup_menu_item_info_destroy, 0);
}

static void
icon_release_cb (GtkEntry *entry,
                 GtkEntryIconPosition position,
#if !GTK_CHECK_VERSION(4,0,0)
                 GdkEventButton *event,
#endif
                 gpointer data)
{
	GtkWidget *popover = data;
	GdkRectangle rect;

	gtk_entry_get_icon_area (entry, GTK_ENTRY_ICON_SECONDARY, &rect);
	gtk_popover_set_pointing_to (GTK_POPOVER (popover), &rect);
#if GTK_CHECK_VERSION(3,22,0)
	NM_LIBNM_COMPAT_UNDEPRECATE(gtk_popover_popup (GTK_POPOVER (popover)));
#else
	gtk_widget_show (GTK_WIDGET (popover));
#endif
}

/**
 * nma_utils_setup_password_storage:
 * @passwd_entry: password #GtkEntry which the icon is attached to
 * @initial_flags: initial secret flags to setup password menu from
 * @setting: #NMSetting containing the password, or NULL
 * @password_flags_name: name of the secret flags (like psk-flags), or NULL
 * @with_not_required: whether to include "Not required" menu item
 * @ask_mode: %TRUE if the entry is shown in ASK mode. That means,
 *   while prompting for a password, contrary to being inside the
 *   editor mode.
 *   If %TRUE, the entry should be sensivive on selected "always-ask"
 *   icon (this is e.f. for nm-applet asking for password), otherwise
 *   not.
 *   If %FALSE, it shall not be possible to select a different storage,
 *   because we only prompt for a password, we cannot change the password
 *   location.
 *
 * Adds a secondary icon and creates a popup menu for password entry.
 * The active menu item is set up according to initial_flags, or
 * from @setting/@password_flags_name (if they are not NULL).
 * If the @setting/@password_flags_name are not NULL, secret flags will
 * be automatically updated in the setting when menu is changed.
 */
void
nma_utils_setup_password_storage (GtkWidget *passwd_entry,
                                  NMSettingSecretFlags initial_flags,
                                  NMSetting *setting,
                                  const char *password_flags_name,
                                  gboolean with_not_required,
                                  gboolean ask_mode)
{
	PasswordStorageData *data;
	GtkWidget *box;
	MenuItem idx;
	NMSettingSecretFlags secret_flags;

	g_return_if_fail (!g_object_get_data (
		G_OBJECT (passwd_entry), PASSWORD_STORAGE_TAG));

	data = g_new0 (PasswordStorageData, 1);
	g_object_set_data_full (G_OBJECT (passwd_entry), PASSWORD_STORAGE_TAG, data, g_free);

	/* Whether entry should be sensitive if "always-ask" is active " */
	data->ask_mode = ask_mode;
	data->with_not_required = with_not_required;

	box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);

#if GTK_CHECK_VERSION(4,0,0)
	data->popup_menu = gtk_popover_new ();
	gtk_widget_set_parent (data->popup_menu, GTK_WIDGET (passwd_entry));
	gtk_popover_set_child (GTK_POPOVER (data->popup_menu), box);

	data->item[ITEM_STORAGE_USER] = gtk_check_button_new_with_label (_(icon_desc_table[ITEM_STORAGE_USER]));
	data->item[ITEM_STORAGE_SYSTEM] = gtk_check_button_new_with_label (_(icon_desc_table[ITEM_STORAGE_SYSTEM]));
	gtk_check_button_set_group (GTK_CHECK_BUTTON (data->item[ITEM_STORAGE_SYSTEM]),
	                            GTK_CHECK_BUTTON (data->item[ITEM_STORAGE_USER]));
	data->item[ITEM_STORAGE_ASK] = gtk_check_button_new_with_label (_(icon_desc_table[ITEM_STORAGE_ASK]));
	gtk_check_button_set_group (GTK_CHECK_BUTTON (data->item[ITEM_STORAGE_ASK]),
	                            GTK_CHECK_BUTTON (data->item[ITEM_STORAGE_USER]));
	if (with_not_required) {
		data->item[ITEM_STORAGE_UNUSED] = gtk_check_button_new_with_label (_(icon_desc_table[ITEM_STORAGE_UNUSED]));
		gtk_check_button_set_group (GTK_CHECK_BUTTON (data->item[ITEM_STORAGE_UNUSED]),
		                            GTK_CHECK_BUTTON (data->item[ITEM_STORAGE_USER]));
	}
#else
	data->popup_menu = gtk_popover_new (GTK_WIDGET (passwd_entry));
	gtk_popover_set_modal (GTK_POPOVER (data->popup_menu), TRUE);
	gtk_container_add (GTK_CONTAINER (data->popup_menu), box);
	gtk_widget_show (box);

	data->item[ITEM_STORAGE_USER] = gtk_radio_button_new_with_label (NULL, _(icon_desc_table[ITEM_STORAGE_USER]));
	gtk_widget_show (data->item[ITEM_STORAGE_USER]);
	data->item[ITEM_STORAGE_SYSTEM] = gtk_radio_button_new_with_label_from_widget (
		GTK_RADIO_BUTTON (data->item[ITEM_STORAGE_USER]), _(icon_desc_table[ITEM_STORAGE_SYSTEM]));
	gtk_widget_show (data->item[ITEM_STORAGE_SYSTEM]);
	data->item[ITEM_STORAGE_ASK] = gtk_radio_button_new_with_label_from_widget (
		GTK_RADIO_BUTTON (data->item[ITEM_STORAGE_USER]), _(icon_desc_table[ITEM_STORAGE_ASK]));
	gtk_widget_show (data->item[ITEM_STORAGE_ASK]);
	if (with_not_required) {
		data->item[ITEM_STORAGE_UNUSED] = gtk_radio_button_new_with_label_from_widget (
			GTK_RADIO_BUTTON (data->item[ITEM_STORAGE_USER]), _(icon_desc_table[ITEM_STORAGE_UNUSED]));
		gtk_widget_show (data->item[ITEM_STORAGE_UNUSED]);
	}
#endif

	gtk_box_append (GTK_BOX (box), data->item[ITEM_STORAGE_USER]);
	gtk_box_append (GTK_BOX (box), data->item[ITEM_STORAGE_SYSTEM]);
	gtk_box_append (GTK_BOX (box), data->item[ITEM_STORAGE_ASK]);
	if (with_not_required)
		gtk_box_append (GTK_BOX (box), data->item[ITEM_STORAGE_UNUSED]);

	popup_menu_item_info_register (data->item[ITEM_STORAGE_USER], setting,
	                               password_flags_name, ITEM_STORAGE_USER, passwd_entry);
	popup_menu_item_info_register (data->item[ITEM_STORAGE_SYSTEM], setting,
	                               password_flags_name, ITEM_STORAGE_SYSTEM, passwd_entry);
	popup_menu_item_info_register (data->item[ITEM_STORAGE_ASK], setting,
	                               password_flags_name, ITEM_STORAGE_ASK, passwd_entry);
	if (with_not_required)
		popup_menu_item_info_register (data->item[ITEM_STORAGE_UNUSED], setting,
		                               password_flags_name, ITEM_STORAGE_UNUSED, passwd_entry);


	g_signal_connect (passwd_entry, "icon-release", G_CALLBACK (icon_release_cb), data->popup_menu);
	g_signal_connect_swapped (passwd_entry, "destroy", G_CALLBACK (gtk_widget_unparent), data->popup_menu);
	gtk_entry_set_icon_activatable (GTK_ENTRY (passwd_entry), GTK_ENTRY_ICON_SECONDARY,
	                                !ask_mode);

	/* Initialize active item for password-storage popup menu */
	if (setting && password_flags_name)
		nm_setting_get_secret_flags (setting, password_flags_name, &secret_flags, NULL);
	else
		secret_flags = initial_flags;

	idx = secret_flags_to_menu_item (secret_flags, with_not_required);
	gtk_check_button_set_active (GTK_CHECK_BUTTON (data->item[idx]), TRUE);
	change_password_storage_icon (passwd_entry, idx);
}

/**
 * nma_utils_menu_to_secret_flags:
 * @passwd_entry: password #GtkEntry which the password icon/menu is attached to
 *
 * Returns secret flags corresponding to the selected password storage menu
 * in the attached icon
 *
 * Returns: secret flags corresponding to the active item in password menu
 */
NMSettingSecretFlags
nma_utils_menu_to_secret_flags (GtkWidget *passwd_entry)
{
	PasswordStorageData *data;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	data = g_object_get_data (G_OBJECT (passwd_entry), PASSWORD_STORAGE_TAG);
	if (data) {
		MenuItem idx = 0;
		int i;

		for (i = 0; i <= ITEM_STORAGE_MAX; i++) {
			if (data->item[i] && gtk_check_button_get_active (GTK_CHECK_BUTTON (data->item[i]))) {
				idx = (MenuItem) i;
				break;
			}
		}

		flags = menu_item_to_secret_flags (idx);
	}

	return flags;
}

/**
 * nma_utils_update_password_storage:
 * @passwd_entry: #GtkEntry with the password
 * @secret_flags: secret flags to set
 * @setting: #NMSetting containing the password, or NULL
 * @password_flags_name: name of the secret flags (like psk-flags), or NULL
 *
 * Updates secret flags in the password storage popup menu and also
 * in the @setting (if @setting and @password_flags_name are not NULL).
 *
 */
void
nma_utils_update_password_storage (GtkWidget *passwd_entry,
                                   NMSettingSecretFlags secret_flags,
                                   NMSetting *setting,
                                   const char *password_flags_name)
{
	PasswordStorageData *data;

	/* Update secret flags (WEP_KEY_FLAGS, PSK_FLAGS, ...) in the security setting */
	if (setting && password_flags_name)
		nm_setting_set_secret_flags (setting, password_flags_name, secret_flags, NULL);

	data = g_object_get_data (G_OBJECT (passwd_entry), PASSWORD_STORAGE_TAG);
	if (data) {
		MenuItem idx;

		idx = secret_flags_to_menu_item (secret_flags, data->with_not_required);
		gtk_check_button_set_active (GTK_CHECK_BUTTON (data->item[idx]), TRUE);
		change_password_storage_icon (passwd_entry, idx);
	}
}

typedef struct {
	GMainLoop *loop;
	int response_id;
} NmaDialogData;

static void
nma_dialog_response (GtkDialog *dialog, int response_id, gpointer user_data)
{
	NmaDialogData *data = user_data;

	data->response_id = response_id;
	g_main_loop_quit (data->loop);
}

int
nma_gtk_dialog_run (GtkDialog *dialog)
{
	NmaDialogData data;

	data.loop = g_main_loop_new (NULL, FALSE);
	g_signal_connect (dialog, "response", G_CALLBACK (nma_dialog_response), &data);

	gtk_window_set_hide_on_close (GTK_WINDOW (dialog), TRUE);
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);
	gtk_window_present (GTK_WINDOW (dialog));

	g_main_loop_run (data.loop);
	g_main_loop_unref (data.loop);

	gtk_widget_hide (GTK_WIDGET (dialog));

	return data.response_id;
}
