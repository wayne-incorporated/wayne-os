# Bazel

## Slotting

All upstream Bazel ebuilds install a binary called `bazel` and so are all in
SLOT 0 as multiple versions cannot co-exist. For Chrome OS, we want the ability
to carry multiple LTS versions of Bazel for long-term compatibility with the
various individual packages that use Bazel. These `dev-util/bazel` ebuilds
differ from upstream in that they install a binary suffixed with the major
version of the release (e.g. `bazel-5`) and have their SLOT set accordingly
(e.g. `SLOT=5`). This means that multiple LTS releases can be installed
simultaneously, but only one of each major version.

## Fork Maintenance

This package will remain forked unless upstream were to adopt a similar SLOT
scheme along with a way for ebuilds dependent on Bazel to declare which versions
of Bazel they are compatible with.
