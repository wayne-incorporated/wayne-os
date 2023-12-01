# Board Overlays

This directory contains board overlays.  When a board is configured using
`setup_board --board <board>` the following overlays are added to the
`make.conf` `PORTDIR_OVERLAY` if they exist:

```
src/overlays/overlay-<board>
src/private-overlays/overlay-<board>-private
```

A private board overlay can augment an existing non-private board overlay,
or can serve as the primary board overlay for a board with no non-private board
overlay.

All board overlays should contain a `toolchain.conf`, specifying the
toolchains required to build that board.  Variants can inherit `toolchain.conf`
from their primary board overlay.

The board and variant names can not have underscores or spaces in them.


## Profiles

Overlays can contain named profiles as subdirectories of the `profiles`
directory.  If the board overlay contains a `base` profile, Portage will use
that by default for the board; otherwise, Portage will use a profile from
`chromiumos-overlay`.

Within a profile, a board overlay will most commonly want to specify
package-specific `USE` flags via `package.use`, mask or unmask package versions
via `package.mask` and `package.unmask`, or mask or unmask keywords via
`package.keywords`.  See `man portage` in the chroot for full details on those
and other files that can appear in a profile.

Profiles in a board overlay must have a file `parent` containing a
list of parent profiles.  Each listed profile may be of the format
`repo-name:profile`, or a relative path to another profile in the same overlay.

Adding a base profile to a board overlay that did not previously have a
profile will require re-running `setup_board` with `--force`.


## `layout.conf`

Overlays should contain a `metadata` directory with a `layout.conf` file
therein.  The `layout.conf` file specifies the `masters` list.  This is a list
of repository names (via `repo-name`).  This list disambiguates the selection of
ebuilds.  When two overlays supply the same ebuild the overlay whose `repo_name`
is listed later in the masters list will be used.  The masters list also effects
the way that portage searches for eclasses.  By having the `chromiumos` overlay
as the last entry in the masters list, portage will correctly find the
chromiumos specific eclasses.


## Board-specific packages

A board overlay will typically want to provide additional packages to
install.  ChromiumOS builds install the `virtual/target-os` package by default,
whose `RDEPEND` brings in all the packages installed by default.
`virtual/target-os` `RDEPEND`s on the virtual package `virtual/chromeos-bsp`,
which exists for board overlays to override.  `chromiumos-overlay` provides a
default version of `virtual/chromeos-bsp` which `RDEPEND`s on the empty package
`chromeos-base/chromeos-bsp-null`.  Board overlays should provide a
`virtual/chromeos-bsp` package that `RDEPEND`s on
`chromeos-base/chromeos-bsp-boardname`, and a
`chromeos-base/chromeos-bsp-boardname` package that `RDEPEND`s on any desired
board-specific packages.

A board overlay can also provide additional packages to install in dev
builds only, via similar packages `virtual/chromeos-bsp-dev` and
`chromeos-base/chromeos-bsp-dev-boardname`.  ChromiumOS dev builds install
`virtual/target-os-dev` by default, which `RDEPEND`s on
`virtual/chromeos-bsp-dev` via means of `virtual/target-chromium-os-dev`.

Similarly, a `virtual/chromeos-bsp-test` package can be provided for
test images.

Note that a board overlay cannot specify package-specific `USE` flags by using
an `RDEPEND` with a use flag, such as `section/package[useflag]`; instead, add
`section/package useflag` to `package.use` in a profile.


## Private host overlays

The host (non-cross-compiling) build environment will use the following
overlay if it exists:

```
src/private-overlays/chromeos-overlay
```

This overlay contains private packages needed on the host system to compile
target packages used in a private overlay.  Packages only needed on the target
system should appear in a private board overlay.

Like a board overlay, a private host overlay must include a `layout.conf`
with `masters` set, so that the packages within that host overlay can reference
eclasses from the parent overlays `chromiumos-overlay` or `portage-stable`.
