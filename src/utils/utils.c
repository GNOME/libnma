/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2007 Red Hat, Inc.
 */

#include <string.h>
#include <glib.h>

#include <nm-setting-connection.h>
#include <nm-setting-wireless-security.h>

#include "crypto.h"
#include "utils.h"
#include "gconf-helpers.h"

/*
 * utils_bin2hexstr
 *
 * Convert a byte-array into a hexadecimal string.
 *
 * Code originally by Alex Larsson <alexl@redhat.com> and
 *  copyright Red Hat, Inc. under terms of the LGPL.
 *
 */
char *
utils_bin2hexstr (const char *bytes, int len, int final_len)
{
	static char	hex_digits[] = "0123456789abcdef";
	char *		result;
	int			i;

	g_return_val_if_fail (bytes != NULL, NULL);
	g_return_val_if_fail (len > 0, NULL);
	g_return_val_if_fail (len < 256, NULL);	/* Arbitrary limit */

	result = g_malloc0 (len * 2 + 1);
	for (i = 0; i < len; i++)
	{
		result[2*i] = hex_digits[(bytes[i] >> 4) & 0xf];
		result[2*i+1] = hex_digits[bytes[i] & 0xf];
	}
	/* Cut converted key off at the correct length for this cipher type */
	if (final_len > -1)
		result[final_len] = '\0';

	return result;
}

static char * vnd_ignore[] = {
	"Semiconductor",
	"Components",
	"Corporation",
	"Corp.",
	"Corp",
	"Inc.",
	"Inc",
	NULL
};

#define DESC_TAG "description"

const char *
utils_get_device_description (NMDevice *device)
{
	char *description = NULL;
	const char *dev_product;
	const char *dev_vendor;
	char *product = NULL;
	char *vendor = NULL;
	char *p;
	char **words;
	char **item;
	GString *str;
	gboolean need_space = FALSE;

	g_return_val_if_fail (device != NULL, NULL);

	description = g_object_get_data (G_OBJECT (device), DESC_TAG);
	if (description)
		return description;

	dev_product = nm_device_get_product (device);
	dev_vendor = nm_device_get_vendor (device);
	if (!dev_product || !dev_vendor)
		return NULL;

	/* Replace stupid '_' with ' ' */
	p = product = g_strdup (dev_product);
	while (*p) {
		if (*p == '_')
			*p = ' ';
		p++;
	}

	p = vendor = g_strdup (dev_vendor);
	while (*p) {
		if (*p == '_' || *p == ',')
			*p = ' ';
		p++;
	}

	str = g_string_new_len (NULL, strlen (vendor) + strlen (product));

	/* In a futile attempt to shorten the vendor ID, ignore certain words */
	words = g_strsplit (vendor, " ", 0);

	for (item = words; *item; item++) {
		int i = 0;
		gboolean ignore = FALSE;

		if (g_ascii_isspace (**item) || (**item == '\0'))
			continue;

		while (vnd_ignore[i] && !ignore) {
			if (!strcmp (*item, vnd_ignore[i]))
				ignore = TRUE;
			i++;
		}

		if (!ignore) {
			g_string_append (str, *item);
			if (need_space)
				g_string_append_c (str, ' ');
			need_space = TRUE;
		}
	}
	g_strfreev (words);

	g_string_append_c (str, ' ');
	g_string_append (str, product);
	description = str->str;
	g_string_free (str, FALSE);

	g_object_set_data_full (G_OBJECT (device),
	                        "description", description,
	                        (GDestroyNotify) g_free);

	g_free (product);
	g_free (vendor);
	return description;
}

static void
clear_one_byte_array_field (GByteArray **field)
{
	g_return_if_fail (field != NULL);

	if (!*field)
		return;
	g_byte_array_free (*field, TRUE);
	*field = NULL;
}

gboolean
utils_fill_one_crypto_object (NMConnection *connection,
                              const char *key_name,
                              gboolean is_private_key,
                              const char *password,
                              GByteArray **field,
                              GError **error)
{
	const char *filename;
	NMSettingConnection *s_con;
	guint32 ignore;

	g_return_val_if_fail (key_name != NULL, FALSE);
	g_return_val_if_fail (field != NULL, FALSE);

	clear_one_byte_array_field (field);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_return_val_if_fail (s_con != NULL, FALSE);

	filename = g_object_get_data (G_OBJECT (connection), key_name);
	if (!filename)
		return TRUE;

	if (is_private_key)
		g_return_val_if_fail (password != NULL, FALSE);

	if (is_private_key) {
		*field = crypto_get_private_key (filename, password, &ignore, error);
		if (error && *error)
			clear_one_byte_array_field (field);
	} else {
		*field = crypto_load_and_verify_certificate (filename, error);
		if (error && *error)
			clear_one_byte_array_field (field);
	}

	if (error && *error)
		return FALSE;
	return TRUE;
}

void
utils_fill_connection_certs (NMConnection *connection)
{
	NMSettingWirelessSecurity *s_wireless_sec;

	g_return_if_fail (connection != NULL);

	s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, 
															    NM_TYPE_SETTING_WIRELESS_SECURITY));
	if (!s_wireless_sec)
		return;

	utils_fill_one_crypto_object (connection,
	                              NMA_PATH_CA_CERT_TAG,
	                              FALSE,
	                              NULL,
	                              &s_wireless_sec->ca_cert,
	                              NULL);
	utils_fill_one_crypto_object (connection,
	                              NMA_PATH_CLIENT_CERT_TAG,
	                              FALSE,
	                              NULL,
	                              &s_wireless_sec->client_cert,
	                              NULL);
	utils_fill_one_crypto_object (connection,
	                              NMA_PATH_PHASE2_CA_CERT_TAG,
	                              FALSE,
	                              NULL,
	                              &s_wireless_sec->phase2_ca_cert,
	                              NULL);
	utils_fill_one_crypto_object (connection,
	                              NMA_PATH_PHASE2_CLIENT_CERT_TAG,
	                              FALSE,
	                              NULL,
	                              &s_wireless_sec->phase2_client_cert,
	                              NULL);
}

void
utils_clear_filled_connection_certs (NMConnection *connection)
{
	NMSettingWirelessSecurity *s_wireless_sec;

	g_return_if_fail (connection != NULL);

	s_wireless_sec = NM_SETTING_WIRELESS_SECURITY (nm_connection_get_setting (connection, 
															    NM_TYPE_SETTING_WIRELESS_SECURITY));
	if (!s_wireless_sec)
		return;

	clear_one_byte_array_field (&s_wireless_sec->ca_cert);
	clear_one_byte_array_field (&s_wireless_sec->client_cert);
	clear_one_byte_array_field (&s_wireless_sec->private_key);
	clear_one_byte_array_field (&s_wireless_sec->phase2_ca_cert);
	clear_one_byte_array_field (&s_wireless_sec->phase2_client_cert);
	clear_one_byte_array_field (&s_wireless_sec->phase2_private_key);
}


