This is meant to be a minimal overlay with packages that have representative
dependencies, but do very little or no work.
Eventually, `build_packages`, `build_images`, and `cros_run_unit_tests` should
take just a few minutes total to execute, but still execute most or all of the
critical code paths in all the processes, including relevant dependency paths
in portage itself.
The board does not have a kernel, so the resulting image is not bootable.

The overlay inherits from amd64-generic to ensure it's configured correctly for
toolchain prebuilts in the sysroot.
All `virtual/target-os[-*]` packages, plus `chromeos-base/autotest-all` are
overridden to eliminate the standard depgraph.
It reuses `sys-apps/baselayout` to ensure the standard CrOS rootfs layout is
created, but otherwise uses only packages within the overlay.

If a kernel is desired in the future, e.g. to more completely execute
`build_images`, a new overlay should be created.
While the use case for it having a kernel is reasonable, the duration of a
kernel build is too long to meet the goals of this overlay.
For this board, `KERN-A` is reserved (`scripts/disk-layout.json`) to skip the
kernel image creation.

TODO:
* Add private overlay to allow private overrides of packages.
* Simple transitive deps
  * `virtual/target [BR]DEPEND pkg1 [BR]DEPEND pkg2`
* Branching deps and transitive deps
  * `virtual/target [BR]DEPEND pkg1 [BR]DEPEND pkg2,pkg3,...,pkgN`
    * `pkg2 [BR]DEPEND pkg2_1,pkg2_2,...,pkg2_M`
    * `pkg3 [BR]DEPEND pkgN3_1,pkg3_2,...,pkg3_X`
    * etc.
* Virtual transitive deps:
  * `virtual/target [BR]DEPEND pkg1 [BR]DEPEND virtual/pkg2 [BR]DEPEND pkg3`
  * Private overlay overrides of the virtual pkg
    * e.g. config-bsp, ec-private-files, etc.
* Virtual switches:
  * `virtual/target [BR]DEPEND virtual/pkg1 [BR]DEPEND pkg2 OR pkg3`
  * e.g. virtual/editor
* Problematic cases?
