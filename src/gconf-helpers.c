/* NetworkManager -- Network link manager
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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <gconf/gconf.h>
#include <gconf/gconf-client.h>
#include <glib.h>

#include "gconf-helpers.h"


gboolean
nm_gconf_get_int_helper (GConfClient *client,
					const char *path,
					const char *key,
					const char *network,
					int *value)
{
	char *		gc_key;
	GConfValue *	gc_value;
	gboolean		success = FALSE;

	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	gc_key = g_strdup_printf ("%s/%s/%s", path, network, key);
	if ((gc_value = gconf_client_get (client, gc_key, NULL)))
	{
		if (gc_value->type == GCONF_VALUE_INT)
		{
			*value = gconf_value_get_int (gc_value);
			success = TRUE;
		}
		gconf_value_free (gc_value);
	}
	g_free (gc_key);

	return success;
}


gboolean
nm_gconf_get_string_helper (GConfClient *client,
					const char *path,
					const char *key,
					const char *network,
					char **value)
{
	char *		gc_key;
	GConfValue *	gc_value;
	gboolean		success = FALSE;

	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);
	g_return_val_if_fail (*value == NULL, FALSE);

	gc_key = g_strdup_printf ("%s/%s/%s", path, network, key);
	if ((gc_value = gconf_client_get (client, gc_key, NULL)))
	{
		if (gc_value->type == GCONF_VALUE_STRING)
		{
			*value = g_strdup (gconf_value_get_string (gc_value));
			success = TRUE;
		}
		gconf_value_free (gc_value);
	}
	g_free (gc_key);

	return success;
}


gboolean
nm_gconf_get_bool_helper (GConfClient *client,
					const char *path,
					const char *key,
					const char *network,
					gboolean *value)
{
	char *		gc_key;
	GConfValue *	gc_value;
	gboolean		success = FALSE;

	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	gc_key = g_strdup_printf ("%s/%s/%s", path, network, key);
	if ((gc_value = gconf_client_get (client, gc_key, NULL)))
	{
		if (gc_value->type == GCONF_VALUE_BOOL)
		{
			*value = gconf_value_get_bool (gc_value);
			success = TRUE;
		}
		gconf_value_free (gc_value);
	}
	g_free (gc_key);

	return success;
}

gboolean
nm_gconf_get_stringlist_helper (GConfClient *client,
				const char *path,
				const char *key,
				const char *network,
				GSList **value)
{
	char *gc_key;
	GConfValue *gc_value;
	gboolean success = FALSE;

	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	gc_key = g_strdup_printf ("%s/%s/%s", path, network, key);
	if (!(gc_value = gconf_client_get (client, gc_key, NULL)))
		goto out;

	if (gc_value->type == GCONF_VALUE_LIST
	    && gconf_value_get_list_type (gc_value) == GCONF_VALUE_STRING)
	{
		GSList *elt;

		for (elt = gconf_value_get_list (gc_value); elt != NULL; elt = g_slist_next (elt))
		{
			const char *string = gconf_value_get_string ((GConfValue *) elt->data);

			*value = g_slist_append (*value, g_strdup (string));
		}

		success = TRUE;
	}

out:
	g_free (gc_key);
	return success;
}

gboolean
nm_gconf_get_bytearray_helper (GConfClient *client,
			       const char *path,
			       const char *key,
			       const char *network,
			       GByteArray **value)
{
	char *gc_key;
	GConfValue *gc_value;
	GByteArray *array;
	gboolean success = FALSE;

	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	gc_key = g_strdup_printf ("%s/%s/%s", path, network, key);
	if (!(gc_value = gconf_client_get (client, gc_key, NULL)))
		goto out;

	if (gc_value->type == GCONF_VALUE_LIST
	    && gconf_value_get_list_type (gc_value) == GCONF_VALUE_INT)
	{
		GSList *elt;

		array = g_byte_array_new ();
		for (elt = gconf_value_get_list (gc_value); elt != NULL; elt = g_slist_next (elt))
		{
			int i = gconf_value_get_int ((GConfValue *) elt->data);
			unsigned char val = (unsigned char) (i & 0xFF);

			if (i < 0 || i > 255) {
				g_log (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
				       "value %d out-of-range for a byte value", i);
				g_byte_array_free (array, TRUE);
				goto out;
			}

			g_byte_array_append (array, (const unsigned char *) &val, sizeof (val));
		}

		*value = array;
		success = TRUE;
	}

out:
	g_free (gc_key);
	return success;
}

gboolean
nm_gconf_set_int_helper (GConfClient *client,
                         const char *path,
                         const char *key,
                         const char *network,
                         int value)
{
	char * gc_key;

	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);

	gc_key = g_strdup_printf ("%s/%s/%s", path, network, key);
	if (!gc_key) {
		g_warning ("Not enough memory to create gconf path");
		return FALSE;
	}
	gconf_client_set_int (client, gc_key, value, NULL);
	g_free (gc_key);
	return TRUE;
}

gboolean
nm_gconf_set_string_helper (GConfClient *client,
                            const char *path,
                            const char *key,
                            const char *network,
                            const char *value)
{
	char * gc_key;

	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	gc_key = g_strdup_printf ("%s/%s/%s", path, network, key);
	if (!gc_key) {
		g_warning ("Not enough memory to create gconf path");
		return FALSE;
	}
	gconf_client_set_string (client, gc_key, value, NULL);
	g_free (gc_key);
	return TRUE;
}

gboolean
nm_gconf_set_bool_helper (GConfClient *client,
                          const char *path,
                          const char *key,
                          const char *network,
                          gboolean value)
{
	char * gc_key;

	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);

	gc_key = g_strdup_printf ("%s/%s/%s", path, network, key);
	if (!gc_key) {
		g_warning ("Not enough memory to create gconf path");
		return FALSE;
	}
	gconf_client_set_bool (client, gc_key, value, NULL);
	g_free (gc_key);
	return TRUE;
}

gboolean
nm_gconf_set_stringlist_helper (GConfClient *client,
                                const char *path,
                                const char *key,
                                const char *network,
                                GSList *value)
{
	char *gc_key;

	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	gc_key = g_strdup_printf ("%s/%s/%s", path, network, key);
	if (!gc_key) {
		g_warning ("Not enough memory to create gconf path");
		return FALSE;
	}

	gconf_client_set_list (client, gc_key, GCONF_VALUE_STRING, value, NULL);
	g_free (gc_key);
	return TRUE;
}

gboolean
nm_gconf_set_bytearray_helper (GConfClient *client,
                               const char *path,
                               const char *key,
                               const char *network,
                               GByteArray *value)
{
	char *gc_key;
	int i;
	GSList *list = NULL;

	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (network != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	gc_key = g_strdup_printf ("%s/%s/%s", path, network, key);
	if (!gc_key) {
		g_warning ("Not enough memory to create gconf path");
		return FALSE;
	}

	for (i = 0; i < value->len; i++)
		list = g_slist_append(list, GINT_TO_POINTER ((int) value->data[i]));

	gconf_client_set_list (client, gc_key, GCONF_VALUE_INT, list, NULL);

	g_slist_free (list);
	g_free (gc_key);
	return TRUE;
}

