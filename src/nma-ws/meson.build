nma_ws_inc = include_directories('.')

sources = [version_header] + files(
  'nma-eap.c',
  'nma-eap-fast.c',
  'nma-eap-leap.c',
  'nma-eap-peap.c',
  'nma-eap-simple.c',
  'nma-eap-tls.c',
  'nma-eap-ttls.c',
  'helpers.c',
  'wireless-security.c',
  'ws-dynamic-wep.c',
  'ws-leap.c',
  'ws-sae.c',
  'ws-wep-key.c',
  'ws-wpa-eap.c',
  'ws-wpa-psk.c'
)

resource_data = files(
  'nma-eap-fast.ui',
  'nma-eap-leap.ui',
  'nma-eap-peap.ui',
  'nma-eap-simple.ui',
  'nma-eap-tls.ui',
  'nma-eap-ttls.ui',
  'ws-dynamic-wep.ui',
  'ws-leap.ui',
  'ws-sae.ui',
  'ws-wep-key.ui',
  'ws-wpa-eap.ui',
  'ws-wpa-psk.ui'
)

sources += gnome.compile_resources(
  'ws-resources',
  'ws.gresource.xml',
  dependencies: resource_data
)

incs = [
  top_inc,
  shared_inc,
  src_inc
]

deps = [
  gtk_dep,
  libnm_dep,
  libutils_libnm_dep
]

libnma_ws_libnm = static_library(
  'wireless-security-libnm',
  sources: sources,
  include_directories: incs,
  dependencies: deps
)

if enable_libnma_gtk4
  deps = [
    gtk4_dep,
    libnm_dep,
    libutils_libnm_dep
  ]

  libnma_ws_libnma_gtk4 = static_library(
    'wireless-security-libnma-gtk4',
    sources: sources,
    include_directories: incs,
    dependencies: deps,
    c_args: cflags
  )
endif
