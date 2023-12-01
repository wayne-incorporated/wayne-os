# Development Image Installer

The dev-install tool is used to install developer tools on a release image.
This is most used by external CrOS users who want to take their existing CrOS
system, put it into dev mode, and then quickly install a bunch of useful tools.

It's generally intended to create the equivalent of a dev image that one would
build using `./build_image ... dev`.
We aren't able to fully recreate that environment currently, but we get close.

It is not meant to create a fully standalone environment where one can build new
packages from source and have them installed.
For that, people should look into [Crouton] or [Crostini] instead.

Note: When we refer to the "stateful" partition, we usually refer to all of the
related content that lives in it.
The `/var` and `/usr/local` paths are actually bind mounted from directories
that live in the stateful partition.
It's used for other things as well, but dev-install only cares about those two
particular paths.

[TOC]

## Environments

In order to understand why we configure certain paths, we need to understand
what environments & constraints we operate under.

There are basically four possible environments we need to consider:

*   Release (base) images where dev mode is **disabled**.
    *   We have strong incentives to keep the rootfs small.
    *   We want to minimize unused packages and programs (e.g. for security).
    *   Nothing developer related should execute here (to maintain security).
    *   The stateful partition is largely empty and may be reset or cleared.
    *   `/usr/local` is never mounted.
*   Release (base) images where dev mode is **enabled**.
    *   Executes with the same exact code/binaries as the image above.
    *   The rootfs is still read-only and remains that way.
    *   Some scripts might change behavior by detecting dev mode state (e.g.
        based on `crossystem "cros_debug?1"`).
    *   `/usr/local` is mounted with exec permissions.
        *   It is initially empty, but state is retained across reboots.
    *   Still no services automatically start up (e.g. no ssh access).
    *   `/var/db/pkg` (that tracks installed packages) is **not** available.
*   Developer images (created via `./build_image dev`).
    *   Starts off as a copy of a base image.
    *   Extra packages (`virtual/target-os-dev`) are installed into `/usr/local`
        for developers to help with ad-hoc testing & verification.
    *   Some rootfs modifications are made to the rootfs to allow extra tools
        under `/usr/local` to work correctly.
    *   A few config settings are enabled to indicate it's a developer image
        (e.g. enable saving of coredumps from crashes).
    *   `/var/db/pkg` (that tracks installed packages) **is** available.
*   Test images (created via `./build_image test`).
    *   Starts off as a copy of a dev image.
    *   More packages (`virtual/target-os-test`) are installed into `/usr/local`
        in order to run automated testing (e.g. autotest & tast).
    *   Some packages are installed into the rootfs.
    *   More rootfs modifications are made to make it easy to access the system
        (e.g. sshd is always started, and a known password & ssh key are added).

## Goals

It's important to emphasize that dev-install is only for helping developers
get easy access to various developer tools when their device is in dev mode.
We must not sacrifice security or stability of the system otherwise.
That is why we strive to have tools be disabled/ineffective normally.

On a non-dev mode system, the `/usr/local` path is never mounted.
This allows us to create dangling symlinks in the rootfs that point to paths
under `/usr/local` without introducing security problems.
Even then, we try to keep this to a minimum.

If we refer back to the [Environments] section, dev-install is designed to:

1.  Not compromise base images when dev mode is disabled.
2.  Allow developers to configure a base image when dev mode is enabled such
    that it looks as much like a developer image as possible.
3.  Not need to modify the rootfs in any way.
4.  Not try and recreate a test image.

In order to achieve these goals, dev-install ends up configuring the base image
in a way that any changes needed in the rootfs are always available there, and
not just when creating a dev image.

## Developer Image Creation

When a developer runs `./build_image ... dev`, the build system will first
create a "base" image which is equivalent to a release image.
The [GPT layout] is initialized as are the various partitions (kernel, rootfs,
EFI, stateful, etc...).
The important part here is that the rootfs is not modified at all from a normal
release setup, and that the stateful partition is empty.
Most notably, `/var` and `/usr/local` will be empty.
Everything in the depgraph of `virtual/target-os` is installed into the rootfs.

When the dev image is created, a copy of the base image is created, and then a
lot of extra packages are installed automatically into the stateful partition.
This means `/usr/local` will be initialized with a lot of packages -- everything
in the depgraph of `virtual/target-os-dev` (except what's already installed into
the rootfs).
We also modify the rootfs a bit to add symlinks to paths under `/usr/local`.

We'll assume that test images are basically the same as dev images, except they
have even more things installed, and some modifications to the rootfs are made.
For example, a well known password & key are installed for automatic ssh access.

### Prebuilt Creation

During `build_image`, we generate the set of installable packages.
See [create_dev_install_lists] for exact implementation details.
Roughly, it builds a list of all the packages by taking the depgraphs of
virtual/target-os-dev & virtual/target-os-test and subtracting the depgraph of
virtual/target-os (since those packages are installed in the rootfs).
That list is saved at `/build/dev-install/package.installable`.

Release builders run the DevInstallerPrebuilts stage.
This reads the set of packages (created above) and uploads their binpkgs to the
`gs://chromeos-dev-installer` bucket.

That bucket uses the layout
`gs://chromeos-dev-installer/board/${BOARD}/${OS_VERSION}/`.
For example, `gs://chromeos-dev-installer/board/eve/12763.0.0/`.

For local developer builds, the full URI is written to `CHROMEOS_DEVSERVER` in
the [lsb-release] file and used by the `dev-install` command at runtime.
The URI will point to the local developer's system, not the release bucket.

For release builds, the value is computed on the fly using [lsb-release].

This is a normal Portage binpkg host repository.

[create_dev_install_lists]: https://chromium.googlesource.com/chromiumos/platform/crosutils/+/release-R80-12739.B/build_library/base_image_util.sh#43

## Image Layout

Depending on whether the rootfs is a base or dev image, the set of available
paths will be different.
This tries to document the current state of the world, not to say that the
status-quo is perfect (we know it's not) or otherwise immutable.

### Base Image

All symlinks on the system at this point are from the dev-install package.
Once that's installed, we also generate package lists and a tarball of the
existing `/usr/local` state (otherwise we'd discard it).

Paths installed by the `dev-install` package:

*   `/etc/bash/bashrc.d/dev-install.sh`: Helper script for shells in dev mode
    to pass along the environment when using plain `sudo`.  Loaded by every
    interactive bash shell.  A bit of a hack.
*   `/etc/env.d/99devinstall`: Adds the `/usr/local/lib*` paths to the
    `LD_LIBRARY_PATH` env var so that extra programs and their libraries that
    are installed under `/usr/local` can find them automatically.  Normally
    only libraries listed in `/etc/ld.so.cache` are automatically loaded, and
    that cache only includes files that are in the rootfs.  This file is added
    to `/etc/profile.env` which in is loaded by `/etc/profile` which is only
    loaded by interactive shells.  Since non-dev mode devices should never have
    any interactive shells run on them, this is OK.

*   `/usr/bin/dev_install`: The main program to download & install packages on
    the fly into `/usr/local`.  This is run manually by end users when they put
    their device into dev mode.

*   `/usr/share/dev-install/portage/`: Various files used to provide a simple
    stub Portage profile.  This allows people to run `emerge` to install the
    various binary packages we make available.
    *   `make.profile/`: A minimalistic Portage profile needed to install the
        binpkgs.  Dynamically loads settings from `/usr/local/` as needed.
        *   `make.defaults`: The main profile file.

*   `/etc/portage/`: This is symlinked to `/usr/share/dev-install/portage/` on
    the device.  We skip this in the build sysroot as that will be the normal
    "full" profile used to compile everything in the SDK.
*   `/usr/local/etc/portage/make.profile/parent`: A stub profile that inherits
    from the rootfs profile.  This allows users to install extra settings after
    the system has been set up.  Only created during `build_image` time.

Paths created on the fly by `build_image`:

*   `/build/dev-install/package.installable`: Not actually installed on the
    device, just created on the fly for use by the build system to determine
    which binpkgs to upload to the server.
*   `dev-only-extras.tar.xz`: Everything in `/usr/local` (except for `/var`).
*   `/usr/share/dev-install/`: The list of packages used by the device are
    computed at this point as the image has been finalized.
    *   `bootstrap.packages`: The set of packages to manually install in order
        to bootstrap Portage.  Once these are installed, `emerge` is used to
        install all the rest of the binpkgs.
    *   `installable_commands`: The list of commands in `PATH` provided by doing
        a `dev_install`.  This is used by the `command_not_found_handle` hook in
        `bashrc` to guide the user towards running `dev_install` when they type
        a command not provided in the base image.
    *   `rootfs.provided/`: For packages that are baked into the rootfs, we
        save different lists in this directory.  This is used by `dev_install`
        at runtime to mark them all as provided.  We have to do this since the
        `/var/db/pkg` metadata is not available.
        *   `chromeos-base.packages`: The `virtual/target-os` packages.

Various python & portage symlinks are created in the rootfs to point to paths
under `/usr/local`.
This is important for scripts that hardcode `#!/usr/bin/python` in their script
shebangs, and for packages that hardcode the path at compile time.
We install these into the base image so they work with `dev_install` too.

*   `/etc/env.d/python`: Python config.
*   `/usr/bin/python*`: Python programs.
*   `/usr/lib/python-exec`: Gentoo Python wrapper.
*   `/usr/lib/portage`: Portage runtime files.
*   `/usr/share/portage/`: Portage settings.

### Dev Image

We install a set of additional symlinks and tweak files for dev images.

*   `/`: A few additional packages from chromeos-base/chromeos-dev-root are
    installed to the rootfs.
    *   `usr/lib/debug`: A symlink to `/usr/local/usr/lib/debug` so debug files
        can be found if available.

*   `/usr/local`: All the virtual/target-os-dev packages are installed here.
    *   `etc/passwd`: Symlink to `/etc/passwd` so dev-only packages which add
        accounts can update the rootfs settings.
    *   `etc/group`: Same as above.
    *   `etc/pam.d/`: Same as above.

There are a few other files that get adapted, but they don't have bearing on
the dev-install process, so we'll ignore them.

## Supported Workflows

Here we outline the expected workflows for developers and what is supported.
Other flows might work, but only the ones detailed here need to be verified.

### Base Image

We expect people to use `dev-install` to install the set of binary packages and
initialize the `/usr/local` tree.
Once it's finished running, `emerge` will be available to install more.
It needs to be able to bootstrap from an empty `/usr/local` tree.

The `/var/db/pkg` will not be available, so packages installed in the rootfs
won't be possible to upgrade.

Developers may use `cros deploy` to install additional packages, or upgrade any
existing ones as long as they were installed to `/usr/local`.

Developers may also use other `cros` helpers as makes sense e.g. `cros flash`.

### Dev Image

A normal dev image will already have the stateful partition set up.

It will have the full `/var/db/pkg` tree available that reflects the state of
the rootfs.

Developers may use `cros deploy` to upgrade packages in the rootfs as well as
`/usr/local`, and may install additional packages to either path.

Running `dev-install` is not required.
If the stateful is wiped (for any reason), then `dev-install` may be used to
reinstall the developer packages.
However, the `/var/db/pkg` path is not restored, so this state will be more
like a base image rather than a dev image.

Developers may also use other `cros` helpers as makes sense e.g. `cros flash`.


[Crouton]: https://github.com/dnschneid/crouton
[Crostini]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/containers_and_vms.md
[Environments]: #Environments
[GPT layout]: https://dev.chromium.org/chromium-os/chromiumos-design-docs/disk-format
[lsb-release]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/os_config.md#LSB
