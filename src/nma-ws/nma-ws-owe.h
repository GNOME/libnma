#ifndef NMA_WS_OWE_H
#define NMA_WS_OWE_H

#include <glib.h>
#include <glib-object.h>
#include <NetworkManager.h>

#include "nma-version.h"

G_BEGIN_DECLS

typedef struct _NMAWsOwe NMAWsOwe;
typedef struct _NMAWsOweClass NMAWsOweClass;

#if defined(G_DEFINE_AUTOPTR_CLEANUP_FUNC) && NMA_VERSION_MIN_REQUIRED >= NMA_VERSION_1_10_6
G_DEFINE_AUTOPTR_CLEANUP_FUNC(NMAWsOwe, g_object_unref)
#endif

#define NMA_TYPE_WS_OWE           (nma_ws_owe_get_type ())
#define NMA_WS_OWE(obj)           (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMA_TYPE_WS_OWE, NMAWsOwe))
#define NMA_WS_OWE_CLASS(klass)   (G_TYPE_CHECK_CLASS_CAST ((klass), NMA_TYPE_WS_OWE, NMAWsOweClass))
#define NMA_IS_WS_OWE(obj)        (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMA_TYPE_OWE))
#define NMA_IS_OWE_CLASS(klass)   (G_TYPE_CHECK_CLASS_TYPE ((klass), NMA_TYPE_WS_OWE))
#define NMA_WS_OWE_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), NMA_TYPE_WS_OWE, NMAWsOweClass))

NMA_AVAILABLE_IN_1_8_36
GType nma_ws_owe_get_type (void);

NMA_AVAILABLE_IN_1_8_36
NMAWsOwe *nma_ws_owe_new (NMConnection *connection);

G_END_DECLS

#endif /* NMA_WS_OWE_H */
