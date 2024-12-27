src_inc = include_directories('.')

version_conf = configuration_data()
version_conf.set('NMA_MAJOR_VERSION', nma_major_version)
version_conf.set('NMA_MINOR_VERSION', nma_minor_version)
version_conf.set('NMA_MICRO_VERSION', nma_micro_version)

version = 'nma-version.h'

version_header = configure_file(
  input: version + '.in',
  output: version,
  configuration: version_conf,
  install_dir: join_paths(nma_includedir, 'libnma')
)

subdir('utils')
subdir('nma-ws')

resource_data = nma_ws_resource_data + files(
  'nma-bar-code-widget.ui',
  'nma-cert-chooser.ui',
  'nma-mobile-wizard.ui',
  'nma-pkcs11-cert-chooser-dialog.ui',
  'nma-pkcs11-token-login-dialog.ui',
  'nma-vpn-password-dialog.ui',
  'nma-wifi-dialog.ui'
)

built_sources = gnome.compile_resources(
  'nma-resources',
  'nma.gresource.xml',
  dependencies: resource_data
)

gir_headers = nma_ws_headers + files(
  'nma.h',
  'nma-bar-code-widget.h',
  'nma-bar-code.h',
  'nma-cert-chooser.h',
  'nma-mobile-providers.h',
  'nma-mobile-wizard.h',
  'nma-ui-utils.h',
  'nma-vpn-password-dialog.h',
  'nma-wifi-dialog.h'
)

install_headers(
  gir_headers,
  subdir: 'libnma'
)

gir_sources = [version_header] + nma_ws_sources + files(
  'init.c',
  'nma-bar-code-widget.c',
  'nma-bar-code.c',
  'nma-cert-chooser.c',
  'nma-cert-chooser-button.c',
  'nma-mobile-providers.c',
  'nma-mobile-wizard.c',
  'nma-ui-utils.c',
  'nma-vpn-password-dialog.c',
  'nma-wifi-dialog.c'
)

pkcs11_sources = files(
  'nma-pkcs11-cert-chooser-dialog.c',
  'nma-pkcs11-token-login-dialog.c'
)

incs = [
  top_inc,
  shared_inc,
  src_inc,
  nma_ws_inc,
]

deps = [
  libnm_dep,
  libutils_libnm_dep,
]

cflags = [
  '-DNMA_COMPILATION',
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB',
  '-DBINDIR="@0@"'.format(nma_bindir),
  '-DDATADIR="@0@"'.format(nma_datadir),
  '-DLIBEXECDIR="@0@"'.format(nma_libexecdir),
  '-DNMALOCALEDIR="@0@"'.format(nma_localedir),
  '-DSYSCONFDIR="@0@"'.format(nma_sysconfdir),
  '-DAUTOSTARTDIR="@0@"'.format(nma_autostartdir),
  '-DICONDIR="@0@"'.format(nma_icondir)
]

symbol_map = join_paths(meson.current_source_dir(), 'libnma.ver')

nma_deps = [ deps, gtk_dep ]
nma_sources = [ gir_sources, built_sources ]
if enable_gcr
  nma_sources += pkcs11_sources
  nma_deps += gcr_dep
endif

libnma = shared_library(
  'nma',
  sources: nma_sources,
  version: libversion,
  include_directories: incs,
  dependencies: nma_deps,
  c_args: cflags,
  link_args: '-Wl,--version-script,' + symbol_map,
  link_depends: symbol_map,
  install: true,
  install_dir: nma_libdir
)

libnma_dep = declare_dependency(
  link_with: libnma,
  include_directories: src_inc
)

if enable_libnma_gtk4
  # This is all a bit clumsy, but what can you do...
  if run_command('test', '-d', join_paths(meson.current_source_dir(), 'libnma-gtk4')).returncode() == 0
    # The distribution contains the GtkBuilder files for Gtk4. Good.
    # We need to translate the names though.
    gtk4_resource_data = []
    foreach f : resource_data
      file_name = '@0@'.format(f)
      path = []
      foreach c : file_name.split('/')
        if path.length() == 0
          path += 'libnma-gtk4'
        else
          path += c
        endif
      endforeach
      gtk4_resource_data += join_paths(path)
    endforeach
    gtk4_data_files = files(gtk4_resource_data)
  else
    # We're probably in a git checkout and need to generate the
    # GtkBuilder files for Gtk4. Oh well...
    gen_3to4 = generator(
      find_program('sh'),
      output: '@PLAINNAME@',
      arguments: [
        '-c',
        'gtk4-builder-tool simplify --3to4 "$0" |grep -v can.default >"$1"',
        '@INPUT@', '@OUTPUT@'
      ]
    )
    gtk4_data_files = custom_target(
      'gtk4-data-files',
      output: ['libnma-gtk4'],
      command: find_program('true'),
      input: gen_3to4.process(
        resource_data,
        preserve_path_from: meson.current_source_dir(),
      )
    )
  endif

  gtk4_built_sources = gnome.compile_resources(
    'nma-gtk4-resources',
    'nma.gresource.xml',
    dependencies: gtk4_data_files,
    source_dir: [
      'libnma-gtk4',
      join_paths(meson.current_build_dir(), 'libnma-gtk4.p')
    ],
  )

  nma_gtk4_deps = [ deps, gtk4_dep ]
  nma_gtk4_sources = [ gir_sources, gtk4_built_sources ]
  if enable_gcr
    nma_gtk4_sources += pkcs11_sources
    nma_gtk4_deps += gcr_dep
  endif

  libnma_gtk4 = shared_library(
    'nma-gtk4',
    sources: nma_gtk4_sources,
    version: libversion,
    include_directories: incs,
    dependencies: nma_gtk4_deps,
    c_args: cflags,
    link_args: '-Wl,--version-script,' + symbol_map,
    link_depends: symbol_map,
    install: true,
    install_dir: nma_libdir
  )

  libnma_gtk4_dep = declare_dependency(
    link_with: libnma_gtk4,
    include_directories: src_inc
  )
endif

subdir('tests')

pkg.generate(
  libraries: libnma,
  version: nma_version,
  name: 'libnma',
  description: 'NetworkManager UI utilities (libnm version)',
  filebase: 'libnma',
  subdirs: 'libnma',
  requires: 'libnm',
  variables: 'exec_prefix=' + nma_prefix,
  install_dir: join_paths(nma_libdir, 'pkgconfig')
)

if enable_libnma_gtk4
  pkg.generate(
    libraries: libnma_gtk4,
    version: nma_version,
    name: 'libnma-gtk4',
    description: 'NetworkManager UI utilities (gtk4 version)',
    filebase: 'libnma-gtk4',
    subdirs: 'libnma',
    requires: 'libnm',
    variables: 'exec_prefix=' + nma_prefix,
    install_dir: join_paths(nma_libdir, 'pkgconfig')
  )
endif

if enable_introspection
  gir_dir = join_paths(nma_datadir, 'gir-' + nma_gir_version)
  typelib_dir = join_paths(nma_libdir, 'girepository-' + nma_gir_version)

  libnma_gir = gnome.generate_gir(
    libnma,
    sources: gir_sources + gir_headers,
    nsversion: nma_gir_version,
    namespace: 'NMA',
    header: 'nma.h',
    includes: [ 'Gtk-3.0', 'NM-1.0' ],
    identifier_prefix: nma_gir_prefix,
    symbol_prefix: nma_gir_prefix.to_lower(),
    export_packages: 'libnma',
    install: true,
    install_dir_gir: gir_dir,
    install_dir_typelib: typelib_dir
  )

  if enable_libnma_gtk4
    libnma_gtk4_gir = gnome.generate_gir(
      libnma_gtk4,
      sources: gir_sources + gir_headers,
      nsversion: nma_gir_version,
      namespace: 'NMA4',
      header: 'nma.h',
      includes: [ 'Gtk-4.0', 'NM-1.0' ],
      identifier_prefix: nma_gir_prefix,
      symbol_prefix: nma_gir_prefix.to_lower(),
      export_packages: 'libnma-gtk4',
      install: true,
      install_dir_gir: gir_dir,
      install_dir_typelib: typelib_dir
    )
  endif
endif

if enable_vapi
  gnome.generate_vapi(
    'libnma',
    sources: libnma_gir[0],
    packages: [ 'libnm', 'gtk+-3.0', 'gio-2.0' ],
    install: true,
  )

  if enable_libnma_gtk4
    gnome.generate_vapi(
      'libnma-gtk4',
      sources: libnma_gtk4_gir[0],
      packages: [ 'libnm', 'gtk4', 'gio-2.0' ],
      install: true,
    )
  endif
endif
