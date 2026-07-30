# Releasing libnma

## Versioning scheme

Starting with 1.12.0, libnma uses a simple sequential micro version:
every tagged micro version is a release (1.12.0, 1.12.1, 1.12.2, ...).
Only even minor numbers are used (1.10, 1.12, 1.14, ...).

Between releases, the version in `meson.build` is always set to the
**next** release number. The workflow is:

1. Development happens with the version already set to the upcoming
   release (e.g. `1.12.1`).
2. When ready to release, tag the current HEAD without any version bump
   commit:

       git tag -s -m "Tag 1.12.1" 1.12.1

3. Immediately after tagging, create a commit that bumps the version to
   the next number:

       # Edit meson.build: version: '1.12.2'
       git commit -am "release: bump version to 1.12.2"

This ensures that `NMA_API_VERSION` (in `nma-version.h`) always
reflects the API available in the current source tree.

## Release pipeline

Pushing a protected tag triggers the GNOME release-service CI component,
which uploads the tarball to download.gnome.org.

## Checklist

- [ ] Ensure NEWS is up to date
- [ ] Verify CI passes on the commit to be tagged
- [ ] Tag the release: `git tag -s -m "Tag X.Y.Z" X.Y.Z`
- [ ] Push the tag: `git push origin X.Y.Z`
- [ ] Bump version in `meson.build` and commit
- [ ] Push the bump commit
