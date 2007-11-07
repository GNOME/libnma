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

#ifndef WS_WEP_KEY_H
#define WS_WEP_KEY_H

typedef enum {
	WEP_KEY_TYPE_HEX = 0,
	WEP_KEY_TYPE_ASCII = 1
} WEPKeyType;

typedef struct {
	struct _WirelessSecurity parent;

	WEPKeyType type;
} WirelessSecurityWEPKey;

WirelessSecurityWEPKey * ws_wep_key_new (const char *glade_file,
                                         NMConnection *connection,
                                         WEPKeyType type);

#endif /* WS_WEP_KEY_H */

