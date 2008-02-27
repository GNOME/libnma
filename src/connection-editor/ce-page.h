/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager Connection editor -- Connection editor for NetworkManager
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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#ifndef __CE_PAGE_H__
#define __CE_PAGE_H__

#include <glib/gtypes.h>
#include <glib-object.h>

#include <gtk/gtkwidget.h>
#include <glade/glade.h>

#include <nm-connection.h>

#define CE_TYPE_PAGE            (ce_page_get_type ())
#define CE_PAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), CE_TYPE_PAGE, CEPage))
#define CE_PAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), CE_TYPE_PAGE, CEPageClass))
#define CE_IS_PAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CE_TYPE_PAGE))
#define CE_IS_PAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), CE_TYPE_PAGE))
#define CE_PAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), CE_TYPE_PAGE, CEPageClass))

typedef struct {
	GObject parent;

	GladeXML *xml;
	GtkWidget *page;
	char *title;

	gboolean disposed;
} CEPage;

typedef struct {
	GObjectClass parent;

	/* Virtual functions */
	gboolean    (*validate)            (CEPage *self);

	void        (*update_connection)   (CEPage *self, NMConnection *connection);
} CEPageClass;

GType ce_page_get_type (void);

GtkWidget *  ce_page_get_page (CEPage *self);

const char * ce_page_get_title (CEPage *self);

gboolean ce_page_validate (CEPage *self);

void ce_page_update_connection (CEPage *self, NMConnection *connection);

#endif  /* __CE_PAGE_H__ */

