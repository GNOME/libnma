#include "nm-default.h"
#include "nma-private.h"

#include "nma-ws.h"
#include "nma-ws-private.h"
#include "nma-ws-owe.h"

struct _NMAWsOwe {
	GtkGrid parent;

	NMConnection *connection;
};

struct _NMAWsOweClass {
	GtkGridClass parent;
};

static void nma_ws_interface_init (NMAWsInterface *iface);

G_DEFINE_TYPE_WITH_CODE (NMAWsOwe, nma_ws_owe, GTK_TYPE_GRID,
                         G_IMPLEMENT_INTERFACE (NMA_TYPE_WS, nma_ws_interface_init))

enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_SECRETS_ONLY,
	PROP_LAST
};

static void
fill_connection (NMAWs *ws, NMConnection *connection)
{
	NMSetting *s_wireless_sec;

	/* Blow away the old security setting by adding a clear one */
	s_wireless_sec = nm_setting_wireless_security_new ();
	g_object_set (s_wireless_sec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "owe",
	              NULL);

	nm_connection_add_setting (connection, s_wireless_sec);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMAWsOwe *self = NMA_WS_OWE (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_object (value, self->connection);
		break;
	case PROP_SECRETS_ONLY:
		g_value_set_boolean (value, FALSE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	NMAWsOwe *self = NMA_WS_OWE (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		self->connection = g_value_dup_object (value);
		break;
	case PROP_SECRETS_ONLY:
		/* OWE does not support setting this property to TRUE. */
		g_return_if_fail (!g_value_get_boolean(value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nma_ws_owe_init (NMAWsOwe *self)
{
}

static void
nma_ws_interface_init (NMAWsInterface *iface)
{
	iface->fill_connection = fill_connection;
	iface->adhoc_compatible = FALSE;
	iface->hotspot_compatible = TRUE;
}

NMAWsOwe *
nma_ws_owe_new (NMConnection *connection)
{
	return g_object_new (NMA_TYPE_WS_OWE,
	                     "connection", connection,
	                     "secrets-only", FALSE,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMAWsOwe *self = NMA_WS_OWE (object);

	g_clear_object (&self->connection);

	G_OBJECT_CLASS (nma_ws_owe_parent_class)->dispose (object);
}

static void
nma_ws_owe_class_init (NMAWsOweClass *klass){
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;

	g_object_class_override_property (object_class,
	                                  PROP_CONNECTION, "connection");

	g_object_class_override_property (object_class,
	                                  PROP_SECRETS_ONLY, "secrets-only");

}
