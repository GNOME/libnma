// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager Applet -- allow user control over networking
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright (C) 2007 - 2021 Red Hat, Inc.
 */

#ifndef UTILS_H
#define UTILS_H

#if !defined(NMA_COMPILATION)
#error "This is an internal header, available only when building libnma."
#endif

#include <net/ethernet.h>

gboolean utils_ether_addr_valid (const struct ether_addr *test_addr);

char *utils_hash_ap (GBytes *ssid,
                     NM80211Mode mode,
                     guint32 flags,
                     guint32 wpa_flags,
                     guint32 rsn_flags);

char *utils_escape_notify_message (const char *src);

char *utils_create_mobile_connection_id (const char *provider,
                                         const char *plan_name);

#define NMA_ERROR (g_quark_from_static_string ("nma-error-quark"))

typedef enum  {
	NMA_ERROR_GENERIC
} NMAError;


gboolean utils_char_is_ascii_ip4_address (char character);
gboolean utils_char_is_ascii_ip6_address (char character);
gboolean utils_char_is_ascii_apn (char character);

typedef gboolean (*UtilsFilterGtkEditableFunc) (char character);
gboolean utils_filter_editable_on_insert_text (GtkEditable *editable,
                                               const gchar *text,
                                               gint length,
                                               gint *position,
                                               void *user_data,
                                               UtilsFilterGtkEditableFunc validate_character,
                                               gpointer block_func);

void utils_override_bg_color (GtkWidget *widget, GdkRGBA *rgba);
void utils_set_cell_background (GtkCellRenderer *cell,
                                const char *color,
                                const char *value);

void widget_set_error   (GtkWidget *widget);
void widget_unset_error (GtkWidget *widget);

gboolean utils_tree_model_get_int64 (GtkTreeModel *model,
                                     GtkTreeIter *iter,
                                     int column,
                                     gint64 min_value,
                                     gint64 max_value,
                                     gboolean fail_if_missing,
                                     gint64 *out,
                                     char **out_raw);

gboolean utils_tree_model_get_address (GtkTreeModel *model,
                                       GtkTreeIter *iter,
                                       int column,
                                       int family,
                                       gboolean fail_if_missing,
                                       char **out,
                                       char **out_raw);

gboolean utils_tree_model_get_ip4_prefix (GtkTreeModel *model,
                                          GtkTreeIter *iter,
                                          int column,
                                          gboolean fail_if_missing,
                                          guint32 *out,
                                          char **out_raw);

GtkFileFilter *utils_cert_filter (void);

GtkFileFilter *utils_key_filter (void);

#endif /* UTILS_H */
