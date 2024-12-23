// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright 2007 - 2019 Red Hat, Inc.
 */

#ifndef NMA_EAP_SIMPLE_H
#define NMA_EAP_SIMPLE_H

#if !defined(NMA_COMPILATION)
#error "This is an internal header, available only when building libnma."
#endif

#include <glib.h>
#include <NetworkManager.h>

#include "nma-ws.h"

typedef enum {
	/* NOTE: when updating this table, also update nma_eap_methods[] */
	NMA_EAP_SIMPLE_TYPE_PAP = 0,
	NMA_EAP_SIMPLE_TYPE_MSCHAP,
	NMA_EAP_SIMPLE_TYPE_MSCHAP_V2,
	NMA_EAP_SIMPLE_TYPE_PLAIN_MSCHAP_V2,
	NMA_EAP_SIMPLE_TYPE_MD5,
	NMA_EAP_SIMPLE_TYPE_PWD,
	NMA_EAP_SIMPLE_TYPE_CHAP,
	NMA_EAP_SIMPLE_TYPE_GTC,
	NMA_EAP_SIMPLE_TYPE_UNKNOWN,

	/* Boundary value, do not use */
	NMA_EAP_SIMPLE_TYPE_LAST
} NMAEapSimpleType;

typedef enum {
	NMA_EAP_SIMPLE_FLAG_NONE            = 0x00,
	/* Indicates the EAP method is an inner/phase2 method */
	NMA_EAP_SIMPLE_FLAG_PHASE2          = 0x01,
	/* Set by TTLS to indicate that inner/phase2 EAP is allowed */
	NMA_EAP_SIMPLE_FLAG_AUTHEAP_ALLOWED = 0x02,
	/* Set from nm-connection-editor or the GNOME network panel */
	NMA_EAP_SIMPLE_FLAG_IS_EDITOR       = 0x04,
	/* Set to indicate that this request is only for secrets */
	NMA_EAP_SIMPLE_FLAG_SECRETS_ONLY    = 0x08
} NMAEapSimpleFlags;

typedef struct _NMAEapSimple NMAEapSimple;

NMAEapSimple *nma_eap_simple_new (NMAWs8021x *ws_8021x,
                                  NMConnection *connection,
                                  NMAEapSimpleType type,
                                  NMAEapSimpleFlags flags,
                                  const char *const*hints);

#endif /* NMA_EAP_SIMPLE_H */
