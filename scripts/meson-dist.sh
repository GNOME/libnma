#!/bin/bash
set -eu

cd "$MESON_DIST_ROOT"

# Remove files not needed in the release tarball
rm -f .editorconfig .gitignore .gitlab-ci.yml
rm -f src/utils/tests/.gitignore

# Generate GTK4 UI files from GTK3 ones using gtk4-builder-tool.
# This makes building from the tarball possible without gtk4-builder-tool.
mkdir -p src/libnma-gtk4/nma-ws

for ui in src/*.ui; do
    gtk4-builder-tool simplify --3to4 "$ui" | grep -v can.default \
        > "src/libnma-gtk4/$(basename "$ui")"
done

for ui in src/nma-ws/*.ui; do
    gtk4-builder-tool simplify --3to4 "$ui" | grep -v can.default \
        > "src/libnma-gtk4/nma-ws/$(basename "$ui")"
done

# Build and include pre-built gtk-doc HTML so building from the
# tarball doesn't require gtk-doc.
ninja -C "$MESON_BUILD_ROOT" libnma-doc
cp -r "$MESON_BUILD_ROOT/html" "$MESON_DIST_ROOT/html"
